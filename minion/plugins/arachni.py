# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


from minion.plugins.base import ExternalProcessPlugin
import os
import re


def _minion_severity(severity):
    if severity == 'Informational':
        return 'Info'
    return severity


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

        if 'target' in self.configuration:
            self.ARACHNI_ARGS.append("--url")
            self.ARACHNI_ARGS.append(self.configuration['target'])

        # General
        if 'only_positives' in self.configuration and self.configuration['only_positives']:
            self.ARACHNI_ARGS.append("--only-positives")

        if 'http_req_limit' in self.configuration:
            self.ARACHNI_ARGS.append("--http-req-limit")
            self.ARACHNI_ARGS.append(str(self.configuration['http_req_limit']))

        if 'http_queue_size'in self.configuration:
            self.ARACHNI_ARGS.append("--http-queue-size")
            self.ARACHNI_ARGS.append(str(self.configuration['http_queue_size']))

        if 'http_timeout' in self.configuration:
            self.ARACHNI_ARGS.append("--http-timeout")
            self.ARACHNI_ARGS.append(str(self.configuration['http_timeout']))

        # TODO : --cookie-jar

        if 'cookie_string' in self.configuration:
            self.ARACHNI_ARGS.append("--http-timeout")
            self.ARACHNI_ARGS.append(self.configuration['cookie_string'])

        if 'user_agent' in self.configuration:
            self.ARACHNI_ARGS.append("--user-agent")
            self.ARACHNI_ARGS.append(self.configuration['user_agent'])

        # TODO : multiple invocations
        if 'custom_header' in self.configuration:
            self.ARACHNI_ARGS.append("--customer-header")
            self.ARACHNI_ARGS.append(self.configuration['custom_header'])

        if 'authed_by' in self.configuration:
            self.ARACHNI_ARGS.append("--authed-by")
            self.ARACHNI_ARGS.append(self.configuration['authed_by'])

        if 'login_check_url' in self.configuration:
            self.ARACHNI_ARGS.append("--login_-check-url")
            self.ARACHNI_ARGS.append(self.configuration['login_check_url'])

        if 'login_check_pattern' in self.configuration:
            self.ARACHNI_ARGS.append("--login-check-pattern")
            self.ARACHNI_ARGS.append(self.configuration['login_check_pattern'])

        # Crawler
        # TODO : multiple invocations
        if 'exclude' in self.configuration:
            self.ARACHNI_ARGS.append("--exclude")
            self.ARACHNI_ARGS.append(self.configuration['exclude'])

        # TODO : multiple invocations
        if 'exclude_page' in self.configuration:
            self.ARACHNI_ARGS.append("--exclude-page")
            self.ARACHNI_ARGS.append(self.configuration['exclude_page'])

        # TODO : multiple invocations
        if 'include' in self.configuration:
            self.ARACHNI_ARGS.append("--include")
            self.ARACHNI_ARGS.append(self.configuration['include'])

        # TODO : multiple invocations
        if 'redundant' in self.configuration:
            self.ARACHNI_ARGS.append("--redundant")
            self.ARACHNI_ARGS.append(self.configuration['redundant'])

        if 'auto_redundant' in self.configuration:
            self.ARACHNI_ARGS.append("--auto-redundant")
            self.ARACHNI_ARGS.append(str(self.configuration['auto_redundant']))

        if 'follow_subdomains' in self.configuration and self.configuration['follow_subdomains']:
             self.ARACHNI_ARGS.append("--follow-sub-domains")

        if 'depth' in self.configuration:
            self.ARACHNI_ARGS.append("--depth")
            self.ARACHNI_ARGS.append(str(self.configuration['depth']))

        if 'link_count' in self.configuration:
            self.ARACHNI_ARGS.append("--link-count")
            self.ARACHNI_ARGS.append(str(self.configuration['link_count']))

        if 'redirect_limit' in self.configuration:
            self.ARACHNI_ARGS.append("--redirect-limit")
            self.ARACHNI_ARGS.append(str(self.configuration['redirect_limit']))

        #TODO : --extends-paths
        #TODO : --restrict-paths

        # Auditor
        if 'audit_links' in self.configuration and self.configuration['audit_links']:
            self.ARACHNI_ARGS.append("--audit-links")

        if 'audit_forms' in self.configuration and self.configuration['audit_forms']:
             self.ARACHNI_ARGS.append("--audit-forms")

        if 'audit_cookies' in self.configuration and self.configuration['audit_cookies']:
             self.ARACHNI_ARGS.append("--audit-cookies")

        # TODO : multiple invocations
        if 'exclude_cookie' in self.configuration:
            self.ARACHNI_ARGS.append("--exclude-cookie")
            self.ARACHNI_ARGS.append(self.configuration['exclude_cookie'])

        # TODO : multiple invocations
        if 'exclude_vector' in self.configuration:
            self.ARACHNI_ARGS.append("--exclude-vector")
            self.ARACHNI_ARGS.append(self.configuration['exclude_vector'])

        if 'audit_headers' in self.configuration and self.configuration['audit_headers']:
             self.ARACHNI_ARGS.append("--audit-headers")

        # Coverage
        if 'audit_cookies_extensively' in self.configuration and self.configuration['audit_cookies_extensively']:
             self.ARACHNI_ARGS.append("--audit-cookies-extensively")

        if 'fuzz_methods' in self.configuration and self.configuration['fuzz_methods']:
             self.ARACHNI_ARGS.append("--fuzz-methods")

        if 'exclude_binaries' in self.configuration and self.configuration['exclude_binaries']:
             self.ARACHNI_ARGS.append("--exclude-binaries")

        # Modules
        if 'modules' in self.configuration:
             self.ARACHNI_ARGS.append("--modules")
             self.ARACHNI_ARGS.append(self.configuration['modules'])

        # Plugins
        if 'plugin' in self.configuration:
             self.ARACHNI_ARGS.append("--plugin")
             self.ARACHNI_ARGS.append(self.configuration['plugin'])

        self.report_progress(22, str(self.ARACHNI_ARGS))
        self.spawn(self.ARACHNI_NAME, self.ARACHNI_ARGS)

    def do_stop(self):
        # Send a nice TERM signal so the ruby script can cleanup.
        # Otherwise it will leave zombie arachni_rpcd processes around.
        self.process.signalProcess('TERM')

    def _format_issue(self, name="", cwe_id="", cwe_url="", severity="", url="", param="", injected="", method="", description="", remediation=""):
        issue = {}
        if name:
            issue["Summary"] = name
        if cwe_id:
            issue["Classification"] = {"cwe_id": cwe_id, "cwe_url": cwe_url}
        if severity:
            issue["Severity"] = severity
        if url:
            url_dict = {"URL": url}
            if param:
                url_dict["Parameter"] = param
            if injected:
                url_dict["Evidence"] = "Code injected : " + injected
            if method:
                url_dict["Extra"] = "Method : " + method
            issue["URLs"] = [url_dict]
        if description:
            issue["Description"] = description
        if remediation:
            issue["Solution"] = remediation

        return issue

    def _parse_output(self, output):
        # "Percent Done:   [#{progress['stats']['progress']}%]"
        # "Current Status: [#{progress['status'].capitalize}]"
        # 'Issues thus far:'
        # "  * #{issue['name']} on '#{issue['url']}'."
        # Percent Done: [-4.27]
        # Current Status: [auditing]
        # Issues: {...}
        # -----[REPORT FOLLOWS]-----

        for data in output.split("\n"):

            issues_line = r"\s+\*\s(.*?)\s\(CWE\sID\s\:\s(\d+)\s-\s(.*?)\)\sfor\sinput\s(.*?)\son" \
                          r"\s(.*?)\s\(Method\s:\s(.*?)\)\swith\s(.*?)\sseverity\sand\sinjected\scode\s(.*?)\." \
                          r"\sDescription\sfor\sthe\sissue\s\:\s(.*?)\sand\sa\sremediation\s\:\s([^-]*)\."
            patt = re.compile(issues_line, re.I|re.U|re.DOTALL)

            for m in patt.finditer(str(data)):
                combined_issue = {m.group(1), m.group(5), m.group(4)}

                if combined_issue not in self.reported_issues:
                    issue = self._format_issue(name=m.group(1), cwe_id=m.group(2), cwe_url=m.group(3),
                                               severity=_minion_severity(m.group(7)), url=m.group(5),
                                               param=m.group(4), injected=m.group(8), method=m.group(6),
                                               description=m.group(9), remediation=m.group(10))
                    self.report_issues([issue])
                    self.reported_issues.append(combined_issue)

    def do_process_stdout(self, data):
        self.output += data

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

    def do_process_stderr(self, data):
        # TODO: Look for ConnectionError and display a message informing the user to launch arachni_rpcd.
        # `initialize': Connection refused - connect(2) (Arachni::RPC::Exceptions::ConnectionError)

        self.stderr += data
        #self.report_errors([str(data)])
        #self.report_finish("Encountered An Error; dying")
        #self.report_issues([{"Summary": data}])

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            self._parse_output(self.output)
            self.report_finish()
        else:
            self.report_finish("FAILED")