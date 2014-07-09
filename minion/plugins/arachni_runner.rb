#!/usr/bin/env ruby

require 'arachni/rpc/pure'
require 'cgi'
require 'pp'
require 'optparse'

options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: arachni_runner.rb [options]"

  # Some sane options
  options["modules"] = ["xss*"]
  options["audit_forms"] = true
  options["audit_links"] = true
  options["audit_cookies"] = true
  options["server"] = "127.0.0.1:7331"

  opt.separator "Supported options:"

  # General
  opt.separator ""
  opt.separator "General -----------------"
  opt.separator ""

  opt.on("--only-positives", "Echo positive results *only*.") do
    options["only_positives"] = true
  end
  opt.on("--http-username string", "Username for HTTP authentication.") do |http_username|
    options["http_username"] = http_username
  end
  opt.on("--http-password string", "Password for HTTP authentication.") do |http_password|
    options["http_password"] = http_password
  end
  opt.on("--http-req-limit integer", "Concurrent HTTP requests limit.") do |http_req_limit|
    options["http_req_limit"] = http_req_limit.to_i
  end
  opt.on("--http-queue-size integer", "Maximum amount of requests to keep in queue.") do |http_queue_size|
    options["http_queue_size"] = http_queue_size.to_i
  end
  opt.on("--http-timeout integer", "HTTP request timeout in milliseconds.") do |http_timeout|
    options["http_timeout"] = http_timeout.to_i
  end
  opt.on("--cookie-jar filepath", "Netscape HTTP cookie file, use curl to create it.") do |filepath|
    options["cookie_jar"] = cookie_jar
  end
  opt.on("--cookie-string name=value,name2=value2", "Cookies, as a string, to be sent to the web application.") do |cookie_string|
    options["cookie_string"] = cookie.string.split(',')
  end
  opt.on("--user-agent string", "Specify user agent.") do |user_agent|
    options["user_agent"] = user_agent
  end
  opt.on("--custom-header name=valuer", "Specify custom headers to be included in the HTTP requests.") do |custom_header|
    header, val = custom_header.to_s.split( /=/, 2 )
    options["header"] = header
    options["val"] = val
  end
  opt.on("--authed_by string", "E-mail address of the person who authorized the scan.") do |authed_by|
    options["authed_key"] = authed_by
  end
  opt.on("--login-check-url url", "A URL used to verify that the scanner is still logged in to the web application.") do |login_check_url|
    options["login_check_url"] = login_check_url
  end
  opt.on("--login-check-pattern regexp", "A pattern used against the body of the 'login-check-url' to verify that the scanner is still logged in to the web application.") do |login_check_pattern|
    options["login_check_pattern"] = login_check_pattern
  end

  # Crawler
  opt.separator ""
  opt.separator "Crawler -----------------"
  opt.separator ""

  opt.on("-e regexp", "--exclude regexp", "Exclude urls matching regexp.") do |exclude|
    options["exclude"] = exclude
  end
  opt.on("--exclude-page regexp", "Exclude pages whose content matches regex.") do |exclude_page|
    options["exclude_page"] = exclude_page
  end
  opt.on("-i regexp", "--include regexp", "Include *only* urls matching regexp.") do |include|
    options["include"] = include
  end
  opt.on("--redundant regex=limit", "Limit crawl on redundant pages likes galleries or catalogs.") do |redundant|
    options["redundant"] = redundant
  end
  opt.on("-f", "--follow_subdomains", "Follow links to subdomains.") do
    options["follow_subdomains"] = true
  end
  opt.on("--depth integer", "Directory depth limit.") do |depth|
    options["depth"] = depth.to_i
  end
  opt.on("--link-count integer", "How many links to follow.") do |link_count|
    options["link_count"] = link_count.to_i
  end
  opt.on("--redirect-limit integer", "How many redirects to follow.") do |redirect_limit|
    options["redirect_limit"] = redirect_limit.to_i
  end
  opt.on("--extend-paths filepath", "Add the paths in file to the ones discovered by the crawler.") do |extend_paths|
    options["extend_paths"] = extend_paths
  end
  opt.on("--restrict-paths filepath", "Use the paths in file instead of crawling.") do |restrict_paths|
    options["restrict_paths"] = restrict_paths
  end
  opt.on("--https-only", "Forces the system to only follow HTTPS URLs.") do
    options["https_only"] = true
  end

  # Auditor
  opt.separator ""
  opt.separator "Auditor -----------------"
  opt.separator ""

  opt.on("-g", "--audit-links", "Audit links.") do
    options["audit_links"] = true
  end
  opt.on("-p", "--audit-forms", "Audit forms.") do
    options["audit_forms"] = true
  end
  opt.on("-c", "--audit-cookies", "Audit cookies.") do
    options["audit_cookies"] = true
  end
  opt.on("--exclude-cookie name", "Cookie to exclude from the audit by name.") do |exclude_cookie|
    options["exclude_cookie"] = exclude_cookie
  end
  opt.on("--exclude-vector name", "Input vector (parameter) not to audity by name.") do |exclude_vector|
    options["exclude_vector"] = exclude_vector
  end
  opt.on("--audit-headers", "Audit HTTP headers.") do
    options["headers"] = true
  end

  # Coverage
  opt.separator ""
  opt.separator "Auditor -----------------"
  opt.separator ""

  opt.on("--audit-cookies-extensively", "Submit all links and forms of the page along with the cookie permutations.") do
    options["audit_cookies_extensively"] = audit_cookies_extensively
  end
  opt.on("--fuzz-methods", "Audit links, forms and cookies using both GET and POST requests.") do
    options["fuzz_methods"] = true
  end
  opt.on("--exclude-binaries", "Exclude non text-based pages from the audit.") do
    options["exclude_binaries"] = true
  end

  # Modules
  opt.separator ""
  opt.separator "Modules -----------------"
  opt.separator ""

  opt.on("-m modname,modname", "--modules modname,modname", "Comma separated list of modules to load.") do |modules|
    options["modules"] = modules.split(',')
  end

  # Plugins
  # TODO : Plugins

  # Platforms
  opt.separator ""
  opt.separator "Platforms -----------------"
  opt.separator ""

  opt.on("--no-fingerprinting", "Disable platform fingerprinting.") do
    options["no_fingerprinting"] = true
  end
  opt.on("--platorms platform,platform", "Comma separated list of platforms (by shortname) to audit.") do |platforms|
    options["platorms"] = platorms.to_s.split(',')
  end

  # Proxy
  opt.separator ""
  opt.separator "Proxy -----------------"
  opt.separator ""

  opt.on("--proxy server:port", "Proxy address to use.") do |proxy|
    options["proxy"] = proxy
  end
  opt.on("--proxy-auth user:passwd", "Proxy authentication credentials.") do |proxy_auth|
    options["proxy_auth"] = proxy_auth
  end
  opt.on("--proxy-type type", "Proxy type; can be http, http_1_0, socks4, socks5, socks4a") do |proxy_type|
    options["proxy_type"] = proxy_type
  end

  # URL to scan
  opt.on("-u", "--url URL", "URL to scan") do |url|
    options["url"] = url
  end

  # RPC Server
  opt.on("--server server:port", "Dispatcher server to use.") do |server|
    options["server"] = server
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

instance_info = dispatcher.call( 'dispatcher.dispatch' )

host, port = instance_info['url'].split( ':' )
instance = Arachni::RPC::Pure::Client.new(
    host:  host,
    port:  port,
    token: instance_info['token']
)

# Avoid having to keep writing instance.call( 'service.<method>', ... )
service = Arachni::RPC::RemoteObjectMapper.new( instance, 'service' )

#puts static_cookies

trap("TERM") do
  print "\nReceived Term Signal.  Shutting down the service..."
  # If this is not done, we will leave extra arachni_rpcd processes lying around.
  service.shutdown
  puts "Done. Exiting"
  exit
end


# Todo : cookies
service.scan options



while sleep 1
    progress = service.progress( with: :issues )

    puts "Percent Done:   [#{progress['stats']['progress']}%]"
    puts "Current Status: [#{progress['status'].capitalize}]"

    if progress['issues'].any?
        puts
        puts 'Issues thus far:'
        progress['issues'].each do |issue|
            puts "  * #{issue['name']} (CWE ID : #{issue['cwe']} - #{issue['cwe_url']}) for input #{issue['var']} on '#{issue['url']}' (Method : #{issue['method']}) with #{issue['severity']} severity and injected code #{issue['injected']}. Description for the issue : #{issue['description'].delete("\n")} and a remediation : #{issue['remedy_guidance'].delete("\n")}."
        end
    end

    puts '-' * 50

    # we're done
    break if !progress['busy']
end

puts "-----[REPORT FOLLOWS]-----"

# Grab the report as a Hash.
pp service.report

# Kill the instance and its process, no zombies please...
service.shutdown


