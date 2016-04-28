class Legit(object):
    def __init__(self, path):
        self.path = path

    def analyse(self):
        # TODO
        # Check file mime type
        # Check unzipped size (before unzip)
        # For each file get the extension and pass it to the normal analyser
        # Then delete the zip archive
        # TODO Refactor Analyser to save the file there (maybe)
        return True