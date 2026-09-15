from tree_sitter import Language,Parser,Query,QueryCursor
import tree_sitter_python as tsp

linguagem=Language(tsp.language())
parser=Parser(linguagem)

code=b"x='select'+djf"
tree=parser.parse(code)


query_str="""
	(assignment
		left: (identifier) @var
		right: (binary_operator
			left: (string) @str
			right: (identifier) @var2)
		(#match? @str "(?i)\\\\bselect\\\\b")
	)
"""

query=Query(linguagem,query_str)
cursor=QueryCursor(query)
captures=cursor.matches(tree.root_node)

for _,node in captures:
	var=node["var"][0]
	str=node["str"][0]
	var2=node["var2"][0]
	num_linha=var.start_point.row+1
	linhas=code.split(b'\n')
	inteira=linhas[var.start_point.row].decode()
	print(f"Captura SQLI: {inteira}")
	print(f" -> var contaminada: {code[var2.start_byte:var2.end_byte].decode()}")
