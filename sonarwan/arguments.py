import argparse


class Arguments(object):
    def __init__(self, json_output, user_patterns_file,
                 user_inference_directory, user_ips_directory,
                 user_urls_directory):
        self.json_output = json_output
        self.user_patterns_file = user_patterns_file
        self.user_inference_directory = user_inference_directory
        self.user_ips_directory = user_ips_directory
        self.user_urls_directory = user_urls_directory

        self.add_final_character()

    def add_final_character(self):
        if self.user_inference_directory and self.user_inference_directory[
                -1] != '/':
            self.user_inference_directory = user_inference_directory + '/'

        if self.user_ips_directory and self.user_ips_directory[-1] != '/':
            self.user_ips_directory = self.user_ips_directory + '/'

        if self.user_urls_directory and self.user_urls_directory[-1] != '/':
            self.user_urls_directory = self.user_urls_directory + '/'

    def create_parser():
        parser = argparse.ArgumentParser(
            description="Recognize devices of a private network by sniffing NAT'd traffic",
            epilog="For suggestions or bug report, go to https://github.com/sonarwan/sonarwan-core"
        )
        parser.add_argument('files', nargs='+', help='List of capture files')
        parser.add_argument("-p", "--patterns", help="User's pattern file")
        parser.add_argument(
            "--ips", help="User's  directory containing ips files")
        parser.add_argument(
            "---urls", help="User's  directory containing urls files")
        parser.add_argument(
            "-i",
            "--inference",
            help="User's directory containing inference csv files")
        parser.add_argument(
            "-j",
            "--json",
            help="outputs information in JSON format.",
            action="store_true")
        return parser
