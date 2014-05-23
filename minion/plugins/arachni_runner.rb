#!/usr/bin/env ruby

require 'arachni/rpc/pure'
require 'cgi'
require 'pp'
require 'optparse'

options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: arachni_runner.rb [options]"
  # Some sane defaults.
  options[:url] = 'http://testfire.net'
  options[:links] = true
  options[:linkcount] = 5
  options[:forms] = true
  options[:audit_cookies] = false
  options[:headers] = false
  options[:modules] = 'xss*'
  options[:subdomains] = false

  opt.on("-u", "--url URL", "URL to scan") do |url|
    options[:url] = url
  end
  opt.on("-a", "--audit-links", "Audit Links?") do
    options[:links] = true
  end
  opt.on("-l", "--link-count 5", "Links to follow") do |link_count|
    options[:linkcount] = link_count.to_i
  end
  opt.on("-f", "--audit-forms", "Audit Forms?") do
    options[:forms] = true
  end
  opt.on("-c", "--audit-cookies", "Audit Cookies?") do
    options[:audit_cookies] = true
  end
  opt.on("-h", "--audit-headers", "Audit Headers?") do
    options[:headers] = true
  end
  opt.on("-m", "--modules MODS", "Arachni Modules to use") do |mods|
    options[:modules] = mods.split(", ")
  end
  opt.on("-s", "--follow-sub-domains", "Follow Sub-Domains?") do
    options[:subdomains] = true
  end

  opt.on('-h', '--help', "Display this screen" ) do
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

dispatcher = Arachni::RPC::Pure::Client.new(
    host: 'localhost',
    port:  7331
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


service.scan url: options[:url],
             audit_links: options[:links],
             link_count_limit: options[:linkcount],
             audit_forms: options[:forms],
             audit_cookies: options[:audit_cookies],
             audit_headers: options[:headers],
             modules: options[:modules],
             follow_subdomains: options[:subdomains],
             cookies: static_cookies,
             exclude: ['SignOut'],
             #proxy_host: '10.2.178.166',
             #proxy_port: '8080',
             debug: false
             


while sleep 1
    progress = service.progress( with: :issues )

    puts "Percent Done:   [#{progress['stats']['progress']}%]"
    puts "Current Status: [#{progress['status'].capitalize}]"

    if progress['issues'].any?
        puts
        puts 'Issues thus far:'
        progress['issues'].each do |issue|
            puts "  * #{issue['name']} for input #{issue['var']} on '#{issue['url']}'."
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


