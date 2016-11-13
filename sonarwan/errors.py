class ServiceDirectoryNotFoundError(Exception):
    pass


class InferenceDirectoryNotFoundError(Exception):
    pass


class PatternFileNotFileError(Exception):
    pass


class InvalidYAMLServiceFile(Exception):
    def __init__(self, filename):
        self.filename = filename


class InvalidCSVInferenceFile(Exception):
    pass


class LinuxDistributionListError(Exception):
    pass
