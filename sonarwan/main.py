from arguments import Arguments
from sonarwan import SonarWan
from logger import logger


def main():
    parser = Arguments.create_parser()
    args = parser.parse_args()
    arguments = Arguments(args.json, args.patterns, args.inference,
                          args.services, args.progress, args.output)

    sonarwan = SonarWan(arguments)
    sonarwan.run(args.files)
    sonarwan.print_info()
    logger.info('SonarWAN ended succesfully')


if __name__ == '__main__':
    main()
