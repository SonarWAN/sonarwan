import argparse


class Arguments(object):
    def __init__(self, json_output, user_patterns_file,
                 user_inference_directory, user_services_directory,
                 progress_output, file_output):

        self.json_output = json_output
        self.progress_output = progress_output
        self.user_patterns_file = user_patterns_file
        self.user_inference_directory = user_inference_directory
        self.user_services_directory = user_services_directory
        self.file_output = file_output

        self.add_final_character()

    def add_final_character(self):
        """ 
        In case user input for directory does not contain '/' at the
        end, it is added.
        """

        if self.user_inference_directory and self.user_inference_directory[
                -1] != '/':
            self.user_inference_directory = user_inference_directory + '/'

        if self.user_services_directory and self.user_services_directory[
                -1] != '/':
            self.user_services_directory = self.user_services_directory + '/'

    def create_parser():

        parser = argparse.ArgumentParser(
            description="Recognize devices of a private network by sniffing NAT'd traffic",
            epilog="For suggestions or bug report, go to https://github.com/sonarwan/sonarwan-core"
        )
        parser.add_argument('files', nargs='+', help='List of capture files')
        parser.add_argument("-p", "--patterns", help="User's pattern file")
        parser.add_argument(
            "-s",
            "--services",
            help="User's directory containing yaml files with IP's and URL's about services"
        )
        parser.add_argument(
            "-i",
            "--inference",
            help="User's directory containing inference csv files")
        parser.add_argument(
            "-j",
            "--json",
            help="Outputs information in JSON format.",
            action="store_true")
        parser.add_argument(
            "-o",
            "--output",
            help="Output file to write report. Works when --json option is NOT set."
        )
        parser.add_argument(
            "--progress",
            help="Updates amount of frames analyzed. Works only with --json option.",
            action="store_true")
        return parser
