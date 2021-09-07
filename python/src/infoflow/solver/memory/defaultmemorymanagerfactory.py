from ...data.flowdroidmemorymanager import FlowDroidMemoryManager 


class DefaultMemoryManagerFactory:

    @staticmethod
    def get_memory_manager(tracing_enabled, erase_path_data):
        return FlowDroidMemoryManager(tracing_enabled, erase_path_data)
