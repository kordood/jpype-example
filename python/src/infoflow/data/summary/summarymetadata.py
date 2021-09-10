class SummaryMetaData:

    def __init__(self, meta_data=None):
        self.exclusive_classes = dict()
        self.exclusive_packages = dict()
        self.class_to_superclass = dict()

        if meta_data is not None:
            self.exclusive_classes.update( meta_data.exclusive_classes )
            self.exclusive_packages.update( meta_data.exclusive_packages )

    def merge(self, original):
        if original is not None:
            self.exclusive_classes.update( original.exclusive_classes )
            self.exclusive_packages.update( original.exclusive_packages )

    def is_class_exclusive(self, class_name):
        if class_name in self.exclusive_classes:
            return True

        temp_name = class_name
        while len(temp_name) != 0:
            idx = temp_name.lastIndexOf( "." )
            if idx < 0:
                break
            temp_name = temp_name[:idx]
            if temp_name in self.exclusive_packages:
                return True

        return False

    def set_superclass(self, name, superclass):
        self.class_to_superclass[name] = superclass

    def get_superclass(self, name):
        return self.class_to_superclass.get(name)

    def merge_hierarchy_data(self, summaries):
        for class_name in self.class_to_superclass.keys():
            clazz_summaries = summaries.get_or_create_class_summaries( class_name )
            if not clazz_summaries.has_superclass():
                clazz_summaries.set_superClass(self.class_to_superclass.get(class_name))

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.exclusive_classes is None:
            if other.exclusive_classes is not None:
                return False
        elif not self.exclusive_classes == other.exclusive_classes:
            return False
        if self.exclusive_packages is None:
            if other.exclusive_packages is not None:
                return False
        elif not self.exclusive_packages == other.exclusive_packages:
            return False
        return True
