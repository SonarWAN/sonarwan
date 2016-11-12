from arguments import Arguments
from sonarwan import SonarWan


def main():
    parser = Arguments.create_parser()
    args = parser.parse_args()
    arguments = Arguments(args.json, args.patterns, args.inference,
                          args.services, args.progress)

    sonarwan = SonarWan(arguments)
    sonarwan.run(args.files)
    sonarwan.print_info()


if __name__ == '__main__':
    main()
