class FormatPrototype:
    def __init__(self, prototype, specifier, position):
        self._prototype = prototype
        if isinstance(specifier, bytes):
            specifier = specifier.decode("latin-1")
        self._specifier = specifier
        self._position = position

    @property
    def prototype(self):
        return self._prototype

    @property
    def specifier(self):
        return self._specifier

    @property
    def position(self):
        return self._position

    def __str__(self):
        return f"FormatPrototype<'{self.prototype}', position: {self.position}>"

    def __repr__(self):
        return self.__str__()
