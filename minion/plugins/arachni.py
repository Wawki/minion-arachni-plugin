# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


from minion.plugin_api import ExternalProcessPlugin
#from urlparse import urlparse
#import subprocess
import os
import re

def _get_test_name(s):
    return s.split('.')[-1]

class ArachniPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "Arachni"
    PLUGIN_VERSION = "0.1"

    ARACHNI_NAME = os.path.dirname(os.path.realpath(__file__)) + "/arachni_runner.rb"
    ARACHNI_ARGS = []

    perc = 0
    status = 'none'
    reported_issues = []
    in_issues = False

    def do_start(self):
        self.output = ""
        self.stderr = ""
        #url = urlparse(self.configuration['target'])
        self.report_progress(10, 'Starting Arachni')
                # Pull some variables from the plan configuration
        if self.configuration.has_key('target'):
             self.ARACHNI_ARGS.append("--url")
             self.ARACHNI_ARGS.append(self.configuration['target'])

        if self.configuration.has_key('audit_links') and self.configuration['audit_links']:
             self.ARACHNI_ARGS.append("--audit-links")

        if self.configuration.has_key('link_count'):
             self.ARACHNI_ARGS.append("--link-count")
             self.ARACHNI_ARGS.append(str(self.configuration['link_count']))

        if self.configuration.has_key('audit_forms') and self.configuration['audit_forms']:
             self.ARACHNI_ARGS.append("--audit-forms")

        if self.configuration.has_key('audit_cookies') and self.configuration['audit_cookies']:
             self.ARACHNI_ARGS.append("--audit-cookies")

        if self.configuration.has_key('audit_headers') and self.configuration['audit_headers']:
             self.ARACHNI_ARGS.append("--audit-headers")

        if self.configuration.has_key('modules'):
             self.ARACHNI_ARGS.append("--modules")
             self.ARACHNI_ARGS.append(self.configuration['modules'])

        if self.configuration.has_key('follow_subdomains') and self.configuration['follow_subdomains']:
             self.ARACHNI_ARGS.append("--follow-sub-domains")

        self.spawn(self.ARACHNI_NAME, self.ARACHNI_ARGS )

    def do_stop(self):
        # Send a nice TERM signal so the ruby script can cleanup.
        # Otherwise it will leave zombie arachni_rpcd processes around.
        self.process.signalProcess('TERM')


    def format_issues(self, issues):
        issues_formal = []
        print "ISSUES: {}".format(issues)
        for issue in issues:
            print "ISSUE: {}".format(issue)
            m = re.match(r".*\sURL: '(.*)'$", issue)
            url = m.group(1)
            issues_formal.append(
                {
                    "Severity": "High",
                    "Summary": issue,
                    "URLs": [url]
                }
            )
        return issues_formal

    def do_process_stdout(self, data):
        # "Percent Done:   [#{progress['stats']['progress']}%]"
        # "Current Status: [#{progress['status'].capitalize}]"
        # 'Issues thus far:'
        # "  * #{issue['name']} on '#{issue['url']}'."
        # Percent Done: [-4.27]
        # Current Status: [auditing]
        # Issues: {...}
        # -----[REPORT FOLLOWS]-----

        print "ARACHNIOUTPUT %s" % (str(data))

        if 'Percent Done:' in str(data):
            perc_line = r"Percent Done:\s+\[\-?(.*)\.(.*)\%\]"
            patt = re.compile(perc_line, re.I|re.U)
            # Sometimes we get blasted with a bunch of output at once.
            # Just return the largest value.
            largest = 0
            for m in patt.finditer(str(data)):
                perc_val = m.group(1)
                if perc_val > largest:
                    largest = perc_val

            if largest > self.perc:
                self.perc = largest

        if 'Current Status:' in str(data):
            stat_line = r"Current Status:\s+\[(.*)\]"
            patt = re.compile(stat_line, re.I|re.U)
            # There is no concept of largest status, so just save the last one.
            for m in patt.finditer(str(data)):
                pass
            
            self.status = m.group(1)
            
            # Percentage and status are always displayed together, so only report progress
            # after receiving both.  Todo: Only update status if it has changed.
            int_perc = 0
            try:
               int_perc = int(self.perc)
            except ValueError:
               int_perc = 0
            self.report_progress(int_perc, self.status)
                 
        if 'Issues thus far:' in str(data):
            self.in_issues = True
            
        if self.in_issues:
            issues_line = r"\s+\*\s(.*)\sfor\sinput\s(.*)\son\s(.*)\."
            patt = re.compile(issues_line, re.I|re.U)
            for m in patt.finditer(str(data)):
                name = m.group(1)
                var = m.group(2)
                url = m.group(3)
                combined_issue = "Reason: {} Var: {} URL: {}".format(name, var, url)
                if combined_issue not in self.reported_issues:
                    self.report_issues(self.format_issues([combined_issue]))
                    self.reported_issues.append(combined_issue)
                else:
                    print "No need to append existing issue: ({})".format(combined_issue)
            
        self.output += data

    def do_process_stderr(self, data):
        # TODO: Look for ConnectionError and display a message informing the user to launch arachni_rpcd.
        # `initialize': Connection refused - connect(2) (Arachni::RPC::Exceptions::ConnectionError)

        self.stderr += data
        print "ARACHNIERROR %s" %(str(data))
        #self.report_errors([str(data)])
        #self.report_finish("Encountered An Error; dying")
        #self.report_issues([{"Summary": data}])

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            with open("stdout.txt", "w") as f:
                f.write(self.output)
            with open("stderr.txt", "w") as f:
                f.write(self.stderr)
            self.report_artifacts("Arachni Output", ["stdout.txt", "stderr.txt"])
            self.callbacks.report_finish()
        else:
            self.report_finish("FAILED")
