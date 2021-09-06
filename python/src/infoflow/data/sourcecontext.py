class SourceContext:
    
    def __init__(self, definition, access_path, stmt, user_data):
        assert access_path is not None

        self.definition = definition
        self.access_path = access_path
        self.stmt = stmt
        self.user_data = user_data
