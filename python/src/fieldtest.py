class InfoflowResults:

	TERMINATION_SUCCESS = 0
	TERMINATION_DATA_FLOW_TIMEOUT = 1
	TERMINATION_DATA_FLOW_OOM = 2
	TERMINATION_PATH_RECONSTRUCTION_TIMEOUT = 4
	TERMINATION_PATH_RECONSTRUCTION_OOM = 8

	def __init__(self, new, value):
		self.const = "hoha"
		self.new = new
		self.value = value


if __name__ == '__main__':
	new = "new"
	value = 1010
	ir = InfoflowResults(new, value)
	print(ir.TERMINATION_PATH_RECONSTRUCTION_TIMEOUT)
	print(InfoflowResults.TERMINATION_PATH_RECONSTRUCTION_TIMEOUT)
	print(ir.new)
	print(InfoflowResults.new)	# cause exception
