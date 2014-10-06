# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


from minion.plugins.base import ExternalProcessPlugin
import os
import re
import uuid
import socket


def _minion_severity(severity):
    severity = severity[0].upper() + severity[1:]
    if severity == 'Informational':
        return 'Info'
    return severity

def _arachni_report_type(report_type):
    if report_type == 'stdout':
        return 'txt'
    elif report_type == 'ap':
        return 'txt'
    elif report_type == 'html':
        return 'html.zip'
    else:
        return report_type

class ArachniPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "Arachni"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "heavy"

    ARACHNI_NAME = os.path.dirname(os.path.realpath(__file__)) + "/arachni_runner.rb"
    ARACHNI_ARGS = []

    perc = 0
    status = 'none'
    reported_issues = []
    in_issues = False

    def do_start(self):
        self.output = ""
        self.stderr = ""
        self.output_id = str(uuid.uuid4())

        self.report_progress(10, 'Starting Arachni')

        # Pull some variables from the plan configuration

        if 'target' in self.configuration:
            self.ARACHNI_ARGS.append("--url")
            self.ARACHNI_ARGS.append(self.configuration['target'])

        if not 'server' in self.configuration:
            raise Exception("Configuration for the dispatcher is missing")
        else:
            self.ARACHNI_ARGS.append("--server")
            self.ARACHNI_ARGS.append(self.configuration['server'])

        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
        else:
            self.report_dir = os.path.dirname(os.path.realpath(__file__)) + "/artifacts/"

        # General
        if 'authorized_by' in self.configuration:
            self.ARACHNI_ARGS.append('--authorized-by')
            self.ARACHNI_ARGS.append(str(self.configuration['authorized_by']))

        # Scope
        if 'scope_include_pattern' in self.configuration:
            for pattern in self.configuration['scope_include_pattern']:
                self.ARACHNI_ARGS.append('--scope-include-pattern')
                self.ARACHNI_ARGS.append(str(pattern))

        if 'scope_include_subdomains' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-include-subdomains')

        if 'scope_exclude_pattern' in self.configuration:
            for pattern in self.configuration['scope_exclude_pattern']:
                self.ARACHNI_ARGS.append('--scope-exclude-pattern')
                self.ARACHNI_ARGS.append(str(pattern))

        if 'scope_exclude_content_pattern' in self.configuration:
            for pattern in self.configuration['scope_exclude_content_pattern']:
                self.ARACHNI_ARGS.append('--scope-exclude-content-pattern')
                self.ARACHNI_ARGS.append(str(pattern))

        if 'scope_exclude_binaries' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-exclude-binaries')

        if 'scope_redundant_path_pattern' in self.configuration:
            for pattern in self.configuration['scope_redundant_path_pattern']:
                self.ARACHNI_ARGS.append('--scope-redundant-path-pattern')
                self.ARACHNI_ARGS.append(str(pattern))

        if 'scope_auto_redundant' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-auto-redundant')
            self.ARACHNI_ARGS.append(self.configuration['scope_auto_redundant'])

        if 'scope_directory_depth_limit' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-directory-depth-limit')
            self.ARACHNI_ARGS.append(self.configuration['scope_directory_depth_limit'])

        if 'scope_page_limit' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-page-limit')
            self.ARACHNI_ARGS.append(self.configuration['scope_page_limit'])

        if 'scope_extend_paths' in self.configuration:
            for path in self.configuration['scope_extend_paths']:
                self.ARACHNI_ARGS.append('--scope-extend-paths')
                self.ARACHNI_ARGS.append(str(path))

        if 'scope_restrict_paths' in self.configuration:
            for path in self.configuration['scope_restrict_paths']:
                self.ARACHNI_ARGS.append('--scope-restrict-paths')
                self.ARACHNI_ARGS.append(str(path))

        if 'scope_url_rewrite' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-url-rewrite')
            self.ARACHNI_ARGS.append(self.configuration['scope_url_rewrite'])

        if 'scope_dom_depth_limit' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-dom-depth-limit')
            self.ARACHNI_ARGS.append(self.configuration['scope_dom_depth_limit'])

        if 'scope_https_only' in self.configuration:
            self.ARACHNI_ARGS.append('--scope-https-only')

        # Audit
        if 'audit_links' in self.configuration:
            self.ARACHNI_ARGS.append('--audit-links')

        if 'audit_forms' in self.configuration:
            self.ARACHNI_ARGS.append('--audit-forms')

        if 'audit_cookies' in self.configuration:
            self.ARACHNI_ARGS.append('--audit-cookies')

        if 'audit_cookies_extensively' in self.configuration:
            self.ARACHNI_ARGS.append('--audit-cookies-extensively')

        if 'audit_headers' in self.configuration:
            self.ARACHNI_ARGS.append('--audit-headers')

        if 'audit_link_template' in self.configuration:
            for template in self.configuration['audit_link_template']:
                self.ARACHNI_ARGS.append('--audit-link-template')
                self.ARACHNI_ARGS.append(str(template))

        if 'audit_with_both_methods' in self.configuration:
            self.ARACHNI_ARGS.append('--audit-with-both-methods')

        if 'audit_exclude_vector' in self.configuration:
            for vector in self.configuration['audit_exclude_vector']:
                self.ARACHNI_ARGS.append('--audit-exclude-vector')
                self.ARACHNI_ARGS.append(str(vector))

        if 'audit_include_vector' in self.configuration:
            for vector in self.configuration['audit_include_vector']:
                self.ARACHNI_ARGS.append('--audit-include-vector')
                self.ARACHNI_ARGS.append(str(vector))

        # Input

        if 'input_value' in self.configuration:
            for value in self.configuration['input_value']:
                self.ARACHNI_ARGS.append('--input-value')
                self.ARACHNI_ARGS.append(str(value))

        if 'input_without_defaults' in self.configuration:
            self.ARACHNI_ARGS.append('--input-without-defaults')

        if 'input_force' in self.configuration:
            self.ARACHNI_ARGS.append('--input-force')

        # Http

        if 'http_user_agent' in self.configuration:
            self.ARACHNI_ARGS.append('--http-user-agent')
            self.ARACHNI_ARGS.append(str(self.configuration['http_user_agent']))

        if 'http_request_concurrency' in self.configuration:
            self.ARACHNI_ARGS.append('--http-request-concurrency')
            self.ARACHNI_ARGS.append(self.configuration['http_request_concurrency'])

        if 'http_request_timeout' in self.configuration:
            self.ARACHNI_ARGS.append('--http-request-timeout')
            self.ARACHNI_ARGS.append(self.configuration['http_request_timeout'])

        if 'http_request_redirect_limit' in self.configuration:
            self.ARACHNI_ARGS.append('--http-request-redirect-limit')
            self.ARACHNI_ARGS.append(self.configuration['http_request_redirect_limit'])

        if 'http_request_queue_size' in self.configuration:
            self.ARACHNI_ARGS.append('--http-request-queue-size')
            self.ARACHNI_ARGS.append(self.configuration['http_request_queue_size'])

        if 'http_request_header' in self.configuration:
            for header in self.configuration['http_request_header']:
                self.ARACHNI_ARGS.append('--http-request-header')
                self.ARACHNI_ARGS.append(str(header))

        if 'http_response_max_size' in self.configuration:
            self.ARACHNI_ARGS.append('--http-response-max-size')
            self.ARACHNI_ARGS.append(self.configuration['http_response_max_size'])

        if 'http_cookie_jar' in self.configuration:
            self.ARACHNI_ARGS.append('--http-cookie-jar')
            self.ARACHNI_ARGS.append(str(self.configuration['http_cookie_jar']))

        if 'http_cookie_string' in self.configuration:
            self.ARACHNI_ARGS.append('--http-cookie-string')
            self.ARACHNI_ARGS.append(str(self.configuration['http_cookie_string']))

        if 'http_authentication_username' in self.configuration:
            self.ARACHNI_ARGS.append('--http-authentication-username')
            self.ARACHNI_ARGS.append(str(self.configuration['http_authentication_username']))

        if 'http_authentication_password' in self.configuration:
            self.ARACHNI_ARGS.append('--http-authentication-password')
            self.ARACHNI_ARGS.append(str(self.configuration['http_authentication_password']))

        if 'http_proxy' in self.configuration:
            self.ARACHNI_ARGS.append('--http-proxy')
            self.ARACHNI_ARGS.append(str(self.configuration['http_proxy']))

        if 'http_proxy_authentication' in self.configuration:
            self.ARACHNI_ARGS.append('--http-proxy-authentication')
            self.ARACHNI_ARGS.append(str(self.configuration['http_proxy_authentication']))

        if 'http_proxy_type' in self.configuration:
            self.ARACHNI_ARGS.append('--http-proxy-type')
            self.ARACHNI_ARGS.append(str(self.configuration['http_proxy_type']))

        # Checks

        if 'checks' in self.configuration:
            self.ARACHNI_ARGS.append('--checks')
            self.ARACHNI_ARGS.append(str(self.configuration['checks']))

        # Platforms

        if 'platforms_no_fingerprinting' in self.configuration:
            self.ARACHNI_ARGS.append('--platforms-no-fingerprinting')

        if 'platforms' in self.configuration:
            self.ARACHNI_ARGS.append('--platforms')
            self.ARACHNI_ARGS.append(str(self.configuration['platforms']))

        # Session

        if 'session_check_url' in self.configuration:
            self.ARACHNI_ARGS.append('--session-check-url')
            self.ARACHNI_ARGS.append(str(self.configuration['session_check_url']))

        if 'session_check_pattern' in self.configuration:
            self.ARACHNI_ARGS.append('--session-check-pattern')
            self.ARACHNI_ARGS.append(str(self.configuration['session_check_pattern']))

        # Browser cluster

        if 'browser_cluster_pool_size' in self.configuration:
            self.ARACHNI_ARGS.append('--browser-cluster-pool-size')
            self.ARACHNI_ARGS.append(str(self.configuration['browser_cluster_pool_size']))

        if 'browser_cluster_job_timeout' in self.configuration:
            self.ARACHNI_ARGS.append('--browser-cluster-job-timeout')
            self.ARACHNI_ARGS.append(str(self.configuration['browser_cluster_job_timeout']))

        if 'browser_cluster_worker_time_to_live' in self.configuration:
            self.ARACHNI_ARGS.append('--browser-cluster-worker-time-to-live')
            self.ARACHNI_ARGS.append(str(self.configuration['browser_cluster_worker_time_to_live']))

        if 'browser_cluster_ignore_images' in self.configuration:
            self.ARACHNI_ARGS.append('--browser-cluster-ignore-images')

        if 'browser_cluster_screen_width' in self.configuration:
            self.ARACHNI_ARGS.append('--browser-cluster-screen-width')
            self.ARACHNI_ARGS.append(str(self.configuration['browser_cluster_screen_width']))

        if 'browser_cluster_screen_height' in self.configuration:
            self.ARACHNI_ARGS.append('--browser-cluster-screen-height')
            self.ARACHNI_ARGS.append(str(self.configuration['browser_cluster_screen_height']))

        # Reports
        if 'reports' in self.configuration:
            self.ARACHNI_ARGS.append("--reports")
            self.ARACHNI_ARGS.append(self.configuration['reports'])

        self.reports = []

        self.spawn(self.ARACHNI_NAME, self.ARACHNI_ARGS)

    def do_stop(self):
        # Send a nice TERM signal so the ruby script can cleanup.
        # Otherwise it will leave zombie arachni_rpcd processes around.
        self.process.signalProcess('TERM')

    def _format_issue(self, name="", cwe_id="", cwe_url="", input_type="", input="", method="", url="", pointing_to="", severity="", injected="", description="", remediation=""):
        issue = {}
        if name:
            issue["Summary"] = name
        if cwe_id:
            issue["Classification"] = {"cwe_id": cwe_id, "cwe_url": cwe_url}
        if severity:
            issue["Severity"] = severity
        if url:
            url_dict = {"URL": url}
            if input:
                url_dict["Parameter"] = input
            if injected:
                url_dict["Evidence"] = "Code injected : " + injected
            if method:
                url_dict["Extra"] = "Input type : " + input_type + " --- " + "Method : " + method + " --- " + "Pointing to : " + pointing_to
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
        # -----[ <report_type> REPORT FOLLOWS ]-----
        # -----[END]-----

        in_report = False

        for data in output.split("\n"):

            # Check issues
            issues_line = r"\s+\*\s(.*?)\s\(CWE\sID\s\:\s(\d+)\s-\s(.*?)\)\sin\s(.*?)\sinput\s(.*?)\using" \
                          r"\s(.*?)\sat\s(.*?)\spointing\sto\s(.*?)\swith\s(.*?)\sseverity\sand\sinjected\scode\s(.*?)\." \
                          r"\sDescription\sfor\sthe\sissue\s\:\s(.*?)\sand\sa\sremediation\s\:\s(.*?)\."
            patt = re.compile(issues_line, re.I|re.U|re.DOTALL)

            for m in patt.finditer(str(data)):

                issue = self._format_issue(name=m.group(1), cwe_id=m.group(2), cwe_url=m.group(3),
                                           input_type=m.group(4), input=m.group(5), method=m.group(6), url=m.group(7),
                                           pointing_to=m.group(8), severity=_minion_severity(m.group(9)),
                                           injected=m.group(10), description=m.group(11), remediation=m.group(12))
                self.report_issues([issue])

            # Check report
            report_regex = r"-----\[\s(.*?)\sREPORT\sFOLLOWS\s\]-----"
            report_match = re.match(report_regex, data)

            # Check end
            end_regex = r"-----\[END]-----"
            end_match = re.match(end_regex, data)

            if report_match is not None:
                report_type = _arachni_report_type(report_match.groups()[0])
                # TODO : Change the extension on report type
                report_path = self.report_dir + report_type.upper() + "_REPORT_" + self.output_id + "." + report_type
                in_report = True

            if in_report and report_match is None:
                if end_match is None:
                    with open(report_path, 'a+') as f:
                        f.write(data)
                        f.write('\n')
                else:
                    in_report = False
                    self.reports.append(report_path)


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

        connection_error_regex = r".*Connection\srefused\s-\sconnect\(2\)"
        if re.match(connection_error_regex, data):
            raise Exception("ConnectionError - You may be need to launch arachni_rpcd")

        inv_token_regex = r".*Token missing or invalid"
        if re.match(inv_token_regex, data):
            raise Exception("InvalidToken - An error occurred on the rpc server side")
        #self.report_errors([str(data)])
        #self.report_finish("Encountered An Error; dying")
        #self.report_issues([{"Summary": data}])

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            self._parse_output(self.output)
            self._save_artifacts()
            self.report_finish()
        else:
            self._save_artifacts()
            failure = {
                "hostname": socket.gethostname(),
                "exception": self.stderr,
                "message": "Plugin failed"
            }
            self.report_finish("FAILED", failure)

    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.output:
            with open(stdout_log, 'w') as f:
                f.write(self.output)
            output_artifacts.append(stdout_log)
        if self.stderr:
            with open(stderr_log, 'w') as f:
                f.write(self.stderr)
            output_artifacts.append(stderr_log)

        if output_artifacts:
            self.report_artifacts("Arachni Output", output_artifacts)
        if self.reports:
            self.report_artifacts("Arachni Reports", self.reports)
