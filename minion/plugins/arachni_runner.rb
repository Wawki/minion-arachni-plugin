#!/usr/bin/env ruby

require 'arachni/rpc/pure'
require 'cgi'
require 'pp'
require 'optparse'

def hms_to_seconds( time )
    a = [1, 60, 3600] * 2
    time.split( /[:\.]/ ).map { |t| t.to_i * a.pop }.inject(&:+)
rescue
    0
end

options = {}
reports = []
timeout = ''

opt_parser = OptionParser.new do |opt|
    opt.banner = "Usage: arachni_runner.rb [options]"

    # Defaults (for arrays & dictionaries ):
        # Scope

    options['scope'] = {}
    options['scope']['include_path_patterns'] = []
    options['scope']['exclude_path_patterns'] = []
    options['scope']['exclude_content_patterns'] = []
    options['scope']['redundant_path_patterns'] = {}
    options['scope']['extend_paths'] = []
    options['scope']['restrict_paths'] = []
    options['scope']['url_rewrites'] = {}

        # Audit

    options['audit'] = {}
    options['audit']['link_templates'] = []
    options['audit']['exclude_vector_patterns'] = []
    options['audit']['include_vector_patterns'] = []

        # Input

    options['input'] = {}
    options['input']['values'] =  {},

        # HTTP

    options['http'] = {}
    options['http']['request_headers'] = {}
    options['http']['cookies'] = {}

        # Session

    options['session'] = {}

        # Browser cluster

    options['browser_cluster'] = {}


    # Some sane options
    options['checks'] = ['xss*']
    options['server'] = '127.0.0.1:7331'

    opt.separator 'Supported options:'

    # General
    opt.separator ''
    opt.separator 'General -----------------'
    opt.separator ''

    opt.on('--authorized-by EMAIL_ADDRESS',
           'E-mail address of the person who authorized the scan.'
    ) do |email_address|
        options['authorized_by'] = email_address
    end

    # Scope
    opt.separator ''
    opt.separator 'Scope -----------------'
    opt.separator ''

    opt.on('--scope-include-pattern PATTERN', Regexp,
           'Only include resources whose path/action matches PATTERN.',
           '(Can be used multiple times.)'
    ) do |pattern|
        options['scope']['include_path_patterns'] << pattern
    end

    opt.on('--scope-include-subdomains',
           'Follow links to subdomain.'
    ) do
        options['scope']['include_subdomains'] = true
    end

    opt.on('--scope-exclude-pattern PATTERN', Regexp,
           'Exclude resources whose path/action matches PATTERN.',
           '(Can be used multiple times.)'
    ) do |pattern|
        options['scope']['exclude_path_patterns'] << pattern
    end

    opt.on('--scope-exclude-content-pattern PATTERN', Regexp,
           'Exclude pages whose content matches PATTERN.',
           '(Can be used multiple times.)'
    ) do |pattern|
        options['scope']['exclude_content_patterns'] << pattern
    end

    opt.on('--scope-exclude-binaries',
           'Exclude non text-based pages.',
           '(Binary content can confuse passive checks that perform pattern matching.)'
    ) do
        options['scope']['exclude_binaries'] = true
    end

    opt.on('--scope-redundant-path-pattern PATTERN:LIMIT',
           'Limit crawl on redundant pages like galleries or catalogs.',
           '(URLs matching PATTERN will be crawled LIMIT amount of times.)',
           '(Can be used multiple times.)'
    ) do |rule|
        pattern, counter = rule.split( ':', 2 )
        options['scope']['redundant_path_patterns'][ Regexp.new( pattern ) ] = Integer( counter )
    end

    opt.on('--scope-auto-redundant LIMIT', Integer,
           'Only follow URLs with identical query parameter names LIMIT amount of times.',
           '(Default: 10)'
    ) do |counter|
        options['scope']['auto_redundant_paths'] = counter || 10
    end

    opt.on('--scope-directory-depth-limit LIMIT', Integer,
           'Directory depth limit.',
           '(Default: inf)',
           '(How deep Arachni should go into the site structure.)'
    ) do |depth|
        options['scope']['directory_depth_limit'] = depth
    end

    opt.on('--scope-page-limit LIMIT', Integer,
           'How many pages to crawl and audit.',
           '(Default: inf)'
    ) do |limit|
        options['scope']['page_limit'] = limit
    end

    opt.on('--scope-extend-paths FILE',
           'Add the paths in FILE to the ones discovered by the crawler.',
           '(Can be used multiple times.)'
    ) do |file|
        options['scope']['extend_paths'] << file
    end

    opt.on('--scope-restrict-paths FILE',
           'Use the paths in FILE instead of crawling.',
           '(Can be used multiple times.)'
    ) do |file|
        options['scope']['restrict_paths'].push(file)
    end

    opt.on('--scope-url-rewrite PATTERN:SUBSTITUTION',
           'Rewrite URLs based on the given PATTERN and SUBSTITUTION.',
           'To convert: http://test.com/articles/some-stuff/23 to http://test.com/articles?id=23',
           'Use:        /articles/\[\w-]+\/(\d+)/:articles.php?id=\1'
    ) do |rule|
        pattern, substitution = rule.split( ':', 2 )
        options['scope']['url_rewrites'][ Regex.new( pattern ) ] = substitution
    end

    opt.on('--scope-dom-depth-limit LIMIT', Integer,
           'How deep to go into the DOM tree of each page, for pages with JavaScript code.',
           "(Setting it to '0' will disable browser analysis.)"
    ) do |limit|
        options['scope']['dom_depth_limit'] = limit
    end

    opt.on('--scope-https-only',
           'Forces the system to only follow HTTPS URLs.'
    ) do
        options['scope']['https_only'] = true
    end

    # Audit
    opt.separator ''
    opt.separator 'Audit -----------------'
    opt.separator ''

    opt.on('--audit-links', 'Audit links.') do
        options['audit']['links'] = true
    end

    opt.on('--audit-forms', 'Audit forms.') do
        options['audit']['forms'] = true
    end

    opt.on('--audit-cookies', 'Audit cookies.') do
        options['audit']['cookies'] = true
    end

    opt.on('--audit-cookies-extensively',
           'Submit all links and forms of the page along with the cookie permutations.',
           '(*WARNING*: This will severely increase the scan-time.)'
    ) do
        options['audit']['cookies_extensively'] = true
    end

    opt.on('--audit-headers', 'Audit headers.') do
        options['audit']['headers'] = true
    end

    opt.on('--audit-link-template TEMPLATE', Regexp,
           'Regular expression with named captures to use to extract input information from generic paths.',
           "To extract the 'input1' and 'input2' inputs from:",
           '  http://test.com/input1/value1/input2/value2',
           'Use:',
           '  /input1\/(?<input1>\w+)\/input2\/(?<input2>\w+)/',
           '(Can be used multiple times.)'
    ) do |pattern|
        options['audit']['link_templates'] |= [pattern]
    end

    opt.on('--audit-with-both-methods',
           'Audit elements with both GET and POST requests.',
           '(*WARNING*: This will severely increase the scan-time.)'
    ) do
        options['audit']['with_both_http_methods'] = true
    end

    opt.on('--audit-exclude-vector PATTERN', Regexp,
           'Exclude input vectors whose name matches PATTERN.',
           '(Can be used multiple times.)'
    ) do |name|
        options['audit']['exclude_vector_patterns'] << name
    end

    opt.on('--audit-include-vector PATTERN', Regexp,
           'Include only input vectors whose name matches PATTERN.',
           '(Can be used multiple times.)'
    ) do |name|
        options['audit']['include_vector_patterns'] << name
    end

    # Input
    opt.separator ''
    opt.separator 'Input -----------------'
    opt.separator ''

    opt.on('--input-value PATTERN:VALUE',
           'PATTERN to match against input names and VALUE to use for them.',
           '(Can be used multiple times.)'
    ) do |rule|
        pattern, value = rule.split( ':', 2 )
        options['input']['values'][Regexp.new(pattern)] = value
    end

    # TODO : Repair
    #opt.on('input-values-file FILE',
    #       'YAML file containing a Hash object with regular expressions,' <<
    #            ' to match agains input names, as keys and input values as values.'
    #) do |file|
    #    options['input']['values']['update_values_from_file'] = file
    #end

    opt.on('--input-without-defaults', 'Do not use the system default input values.') do
        options['input']['without_defaults'] = true
    end

    opt.on('--input-force', 'Fill-in even non-empty inputs.' ) do
        options['input']['force'] = true
    end

    # HTTP
    opt.separator ''
    opt.separator 'HTTP -----------------'
    opt.separator ''

    opt.on('--http-user-agent USER_AGENT',
         "Value for the 'User-Agent' HTTP request header."
    ) do |user_agent|
        options['http']['user_agent'] = user_agent
    end

    opt.on('--http-request-concurrency MAX_CONCURRENCY', Integer,
           'Maximum HTTP request concurrency.',
           '(Be careful not to kill your server.)',
           '(*NOTE*: If your scan seems unresponsive try lowering the limit.)'
    ) do |concurrency|
        options['http']['request_concurrency'] = concurrency
    end

    opt.on('--http-request-timeout TIMEOUT', Integer,
           'HTTP request timeout in milliseconds.'
    ) do |timeout|
        options['http']['request_timemout'] = timeout
    end

    opt.on('--http-request-redirect-limit LIMIT', Integer,
           'Maximum amount of redirects to follow for each HTTP request.'
    ) do |limit|
        options['http']['request_redirect_limit'] = limit
    end

    opt.on('--http-request-queue-size QUEUE_SIZE', Integer,
           'Maximum amount of requests to keep in the queue.',
           'Bigger size means better scheduling and better performance,',
           'smaller means less RAM consumption.'
    ) do |size|
        options['http']['request_queue_size'] = size
    end

    opt.on("--http-request-header NAME=VALUE", "Specify custom headers to be included in the HTTP requests.") do |user_agent|
        header, val = user_agent.split( '=', 2 )
        options['http']['request_headers'][header] = val
    end

    opt.on('--http-response-max-size LIMIT', Integer,
           'Do not download response bodies larger than the specified LIMIT, in bytes.',
           '(Default: inf)'
    ) do |size|
        options['http']['reponse_max_size'] = size
    end

    opt.on('--http-cookie-jar COOKIE_JAR_FILE',
           'Netscape-styled HTTP cookiejar file.'
    ) do |file|
        options['http']['cookie_jar_filepath'] = file
    end

    opt.on('--http-cookie-string COOKIE',
           "Cookie representation as an 'Cookie' HTTP request header."
    ) do |cookie|
        options['http']['cookie_string'] = cookie
    end

    opt.on('--http-authentication-username USERNAME',
           'Username for HTTP authentication.'
    ) do |username|
        options['http']['authentication_username'] = username
    end

    opt.on('--http-authentication-password PASSWORD',
           'Password for HTTP authentication.'
    ) do |password|
        options['http']['authentication_password'] = password
    end

    opt.on('--http-proxy ADDRESS:PORT', 'Proxy to use.') do |url|
        options['http']['proxy'] = url
        options['http']['proxy_host'], options['http']['proxy_port'] = url.split( ':', 2 )
    end

    opt.on('--http-proxy-authentication USERNAME:PASSWORD',
           'Proxy authentication credentials.'
    ) do |credentials|
        options['http']['proxy_username'], options['http']['proxy_password'] = credentials.split( ':', 2 )
    end

    opt.on('--http-proxy-type http,http_1_0,socks4,socks5,socks4a',
           'Proxy type.', '(Default: auto)'
    ) do |type|
        options["http"]["proxy_type"] = type
    end

    # Checks
    opt.separator ''
    opt.separator 'Checks -----------------'
    opt.separator ''

    opt.on('--checks CHECK,CHECK2,...', 'Comma separated list of checks to load.') do |checks|
        options['checks'] = checks.split(',')
    end

    # TODO : PLugins

    # Platforms
    opt.separator ''
    opt.separator 'Platforms -----------------'
    opt.separator ''

    opt.on('--platforms-no-fingerprint',
           'Disable platform fingerprinting.',
           '(By default, the system will try to identify the deployed server-side platforms automatically',
           'in order to avoid sending irrelevant payloads.)'
    ) do
        options['no_fingerprinting'] = true
    end

    opt.on('--platforms PLATFORM,PLATFORM2,...',
           'Comma sperated list of platforms (by shortname) to audit.',
           '(The given platforms will be used *in addition* to fingerprinting. In order to restrict the audit to',
           "these platforms enable the '--platforms-no-fingerprinting' option.')"
    ) do |platforms|
        options['platforms'] = platforms.split( ',' )
    end

    # Session
    opt.separator ''
    opt.separator 'Session -----------------'
    opt.separator ''

    opt.on('--session-check-url URL', String,
           'URL to use to verify that the scanner is still logged in to the web application.',
           "(Requires 'session-check-pattern'.)"
    ) do |url|
        options['session']['check_url'] = url.to_s
    end

    opt.on('--session-check-pattern PATTERN', Regexp,
           "Pattern used agains the body of the 'session-check-url'",
           'to verify that the scanner is still logged in to the web application.',
           "(Requires 'session-check-url'.)"
    ) do |pattern|
        options['session']['check_pattern'] = pattern
    end

    # Browser cluster
    opt.separator ''
    opt.separator 'Browser cluster -----------------'
    opt.separator ''

    opt.on('--browser-cluster-pool-size SIZE', Integer,
           'Amount of browser workers to keep in the pool and put to work.'
    ) do |pool_size|
        options['browser_cluster']['pool_size'] = pool_size
    end

    opt.on('--browser-cluster-job-timeout SECONDS', Integer,
           'Maximum allowed time for each job.'
    ) do |job_timeout|
        options['browser_cluster']['job_timeout'] = job_timemout
    end

    opt.on('--browser-cluster-worker-time-to-live LIMIT', Integer,
           'Re-spawn the browser of each worker every LIMIT jobs.'
    ) do |worker_time_to_live|
        options['browser_cluster']['worker_time_to_live'] = worker_time_to_live
    end

    opt.on('--browser-cluster-ignore-images', 'Do not load images.' ) do
        options['browser_cluster']['ignore_images'] = true
    end

    opt.on('--browser-cluster-screen-width', Integer,
           'Browser screen width.'
    ) do |width|
        options['browser_cluster']['screen_width'] = width
    end

    opt.on('--browser-cluster-screen-height', Integer,
           'Browser screen height.'
    ) do |height|
        options['browser_cluster']['screen_height'] = height
    end

    # TODO : Can suspend scan
    # Set timeout for the scan
    opt.on('--timeout TIMEOUT', 'timeout in HOURS:MINUTES:SECONDS') do |time|
        timeout = hms_to_seconds( time )
    end

    # URL to scan
    opt.separator ''
    opt.separator 'URL -----------------'
    opt.separator ''

    opt.on('-u', '--url URL', 'URL to scan') do |url|
        options['url'] = url
    end

    # RPC Server
    opt.on('--server server:port', 'Dispatcher server to use.') do |server|
        options["server"] = server
    end

    # Reports
    opt.on('--reports REPORT1,REPORT2', 'Type of the report you want to have.') do |report_list|
        reports = report_list.split(',')
    end

    opt.on_tail('-h', '--help', "Output this." ) do
        puts opt
        exit
    end
end

opt_parser.parse!
pp options



# You must have arachni_rpcd running for this to work.
# This currently relies on the experimental branch of arachni.
# https://github.com/Arachni/arachni/tree/experimental#source


# TODO: Read cookies from a file or from the argument list.
static_cookies = [
    {
           "Cookie1"=>"true",
    },
    {
           # Arachni automatically escapes values.  If your values are already escaped, you
           # may want to un-escape them before sending them to arachni.
           "Cookie2"=>CGI::unescape("v%3D2"),
    }
]

host, port = options["server"].split( ':' )
dispatcher = Arachni::RPC::Pure::Client.new(
    host: host,
    port: port
)

begin
    instance_info = dispatcher.call( 'dispatcher.dispatch' )
rescue => conn_e
    abort conn_e.to_s
end

host, port = instance_info['url'].split( ':' )
instance = Arachni::RPC::Pure::Client.new(
    host:  host,
    port:  port,
    token: instance_info['token']
)

# Avoid having to keep writing instance.call( 'service.<method>', ... )
#service = Arachni::RPC::RemoteObjectMapper.new( instance, 'service' )

#puts static_cookies

trap("TERM") do
      print "\nReceived Term Signal.  Shutting down the service..."
      # If this is not done, we will leave extra arachni_rpcd processes lying around.
      instance.call('service.shutdown')
      puts "Done. Exiting"
      exit
end

options.delete("server")

# Todo : cookies
begin
    instance.call('service.scan', options)
rescue => inv_e
    abort inv_e.to_s
end

issue_digests = []

# Initialize timeout
timeout_time = Time.now + timeout.to_i

while sleep 1
    issues = instance.call('service.progress', with: :issues, without: { issues: issue_digests })['issues']

    if not(issues.nil?) && issues.any?
        #puts progress

        issue_digests |= issues.map { |issue| issue['digest'] }

        puts
        puts 'Issues thus far:'
        issues.each do |issue|
            print "  * #{issue['name'] or '-'} (CWE ID : #{issue['cwe'] or '0'} - #{issue['cwe_url'] or '-'}) "
            print "in #{issue['vector']['type'] or '-'} input #{issue['vector']['affected_input_name'] or '-'} "
            print "using #{(issue['vector']['method'] or '-').upcase} at #{issue['vector']['url'] or '-'} "
            print "pointing to #{issue['vector']['action'] or '-'} with #{issue['severity'] or '-'} "
            print "severity and injected code #{issue['vector']['seed'] or '-'}. "
            print "Description for the issue : #{(issue['description'] or '-').gsub("\n"," ")} "
            print "and a remediation : #{(issue['remedy_guidance'] or '-').gsub("\n"," ")} "
            print "and code : #{issue['vector']['html'].gsub("\n", "[#nl#]") or '-'}"
            print "\n"
        end

        puts '-' * 50
    end

    # check timeout
    if timeout && Time.now >= timeout_time
        $stderr.puts "Timeout - Scan took too long"
        break
    end

    # we're done
    break if !instance.call('service.busy?')
end

puts "-----[ txt REPORT FOLLOWS ]-----"

# Grab the report as a Hash.
pp instance.call('service.report')

reports.each do |report_type|
    puts "-----[ " + report_type + " REPORT FOLLOWS ]-----"
    puts instance.call('service.report_as', report_type)
end

puts "-----[END]-----"

# Kill the instance and its process, no zombies please...
instance.call('service.shutdown')

