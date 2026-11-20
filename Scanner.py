from rich.console import Console
from rich.table import Table
from tree_sitter import Language,Parser,QueryCursor,Query
from datetime import datetime
from pathlib import Path
from fpdf import FPDF
import tree_sitter_python as py
import tree_sitter_php as php
import tree_sitter_java as java
import tree_sitter_javascript as js
import typer as tp
import sqlite3
import json

app=tp.Typer()

console=Console()
table=Table()
table.add_column("[white]file_name[/white]")
table.add_column("[white]file_path[/white]")
table.add_column("[white]language[/white]")
table.add_column("[white]vulnerable_code[/white]")
table.add_column("[white]line_number[/white]")
table.add_column("[white]vulnerability_type[/white]")
table.add_column("[white]severity[/white]")
table.add_column("[white]created_at[/white]")

db_name="vulnerabilidades.db"
json_name="relatorio.json"

def Criar_db():
	db=sqlite3.connect(db_name)
	sql="""
		create table if not exists capturas(
			id integer primary key autoincrement,
			file_name text,
			file_path text,
			language text,
			vulnerable_code text,
			line_number integer,
			vulnerability_type text,
			severity text,
			created_at datetime
		)
	""" 
	db.execute(sql)
	db.commit()
	db.close()
Criar_db()

def Salvar_db(nome: str,caminho: str,linguagem: str,codigo: str,linha: int,tipo: str,gravidade: str):
	db=sqlite3.connect(db_name)
	sql="""
		insert into capturas (
			file_name,
			file_path,
			language,
			vulnerable_code,
			line_number,
			vulnerability_type,
			severity,
			created_at
		) 
		values (?,?,?,?,?,?,?,?)
	"""
	db.execute(sql,(nome,caminho,linguagem,codigo,linha,tipo,gravidade,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
	db.commit()
	db.close()

def Python1(arquivo):
	arquivo_b=arquivo.read_bytes()
	linguagem=Language(py.language())
	parser=Parser(linguagem)
	tree=parser.parse(arquivo_b)
	query_ler="""
	  (module

	    (expression_statement 
	      (assignment
	        left: (identifier) @esq
	        right: [(binary_operator (identifier [(string) (integer) (float)] @tipo) @origem) @str (string (interpolation (identifier  [(string) (int) (float)] @tipo) @origem)) @str]
	      )
	    )

	    (expression_statement
	      (call
	        function: (attribute
	          attribute: (identifier) @func)
	        arguments: 
	          (argument_list
	            (identifier) @arg
	          )
	      )
	    )

	    (#match? @str "(?i)\\\\b(select|update|insert|delete)\\\\b")
	    (#match? @func "execute|executemany|read_sql") 
	   (#eq? @esq @arg)
	  )

	  (module

	    (function_definition
	      body:
	        (block
	          (expression_statement 
	            (assignment
	              left: (identifier) @esq
	              right: [(binary_operator (identifier) @origem) @str (string (interpolation (identifier) @origem)) @str]
	            )
	          )

	          (expression_statement
	            (call
	              function: (attribute
	                attribute: (identifier) @func)
	              arguments: 
	                (argument_list
	                  (identifier) @arg
	                )
	            )
	          )
		)
	    )

	    (#match? @str "(?i)\\\\b(select|update|insert|delete)\\\\b")
	    (#match? @func "execute|executemany|read_sql") 
	   (#eq? @esq @arg)
	  )
	 """
	query=Query(linguagem,query_ler)
	cursor=QueryCursor(query)
	matches=cursor.matches(tree.root_node)

	vistos=set()

	if matches is not None:
		for _,match in matches: 
			str_node=match["str"][0]
			origem=match["origem"][0]
			tipo=match["tipo"][0]
			var=arquivo_b[origem.start_byte:origem.end_byte].decode()
			linha=str_node.start_point.row+1
			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode() 
	   		
			chave=(trecho,linha)
			if chave in vistos:
				continue
			vistos.add(chave)
	   
		for codigo,row in vistos:
			if tipo=="str":
				cor="bold orange3"
				severity="HIGH"
			elif tipo=="int" or type(var)=="float":
				cor="bold green"
				severity="LOW"
			else:
				cor="bold green"
				severity="LOW"
			table.add_row(arquivo.stem,str(arquivo),"Python",codigo,str(row),"SQL INJECTION",severity,datetime.now().strftime("%H:%M:%S %d-%m-%Y"),style=cor)
			Salvar_db(arquivo.stem,str(arquivo),"Python",codigo,str(row),"SQL INJECTION",severity)
#
#def Python2(arquivo):
#	arquivo_b=arquivo.read_bytes()
#	linguagem=Language(py.language())
#	parser=Parser(linguagem)
#	tree=parser.parse(arquivo_b)
#	query_ler="""
#	  (module
#
#	    (fuction_definition
#	      parameters: (identifier) @var1
#
#	    (expression_statement
#	      (call
#	        function: (attribute
#	          attribute: (identifier) @func)
#	        arguments: (argument_list
#	           [(binary_operator (identifier) @var2) @str (string (interpolation (identifier) @var2) @str])
#
#	    (#match? @str "(?i)\\\\b(select|update|insert|delete)\\\\b")
#	    (#match? @func "execute|executemany|read_sql") 
#	   (#eq? @var1 @var2)
#	  )
#	 """
#	query=Query(linguagem,query_ler)
#	cursor=QueryCursor(query)
#	matches=cursor.matches(tree.root_node)
#
#	vistos=set()
#
#	if matches is not None:
#		for _,match in matches: 
#			str_node=match["str"][0]
#			origem=match["var1"][0]
#
#			var=arquivo_b[origem.start_byte:origem.end_byte].decode()
#			linha=str_node.start_point.row+1
#			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode() 
#	   		
#			chave=(trecho,linha)
#			if chave in vistos:
#				continue
#			vistos.add(chave)
#	   
#		for codigo,row in vistos:
#			if type(var)=="str":
#				cor="bold yellow"
#				severity="MEDIUM"
#			elif type(var)=="int" or type(var)=="float":
#				cor="bold green"
#				severity="LOW"
#			table.add_row(arquivo.stem,str(arquivo),"Python",str(row),"SQL INJECTION",severity,style="yellow")
#			Salvar_db(arquivo.stem,str(arquivo),"Python",str(row),"SQL INJECTION",severity)
##
##def Python_Block(arquivo):
##	arquivo_b=arquivo.read_bytes()
##	linguagem=Language(py.language())
##	parser=Parser(linguagem)
##	tree=parser.parse(arquivo_b)
##	query_ler=""
##	  (block
##	        (expression_statement
##	         (assignment
##	          left: (identifier) @esq
##	          right: [(binary_operator) @str (string (interpolation)) @str]))
##	    
##	   (expression_statement
##	    (call
##	     function: (attribute
##	      attribute: (identifier) @func)
##	      arguments: (argument_list
##	       (identifier) @arg)))
##	    (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
##	    (#eq? @func "execute")
##	    
##	   (#eq? @esq @arg)
##	  )
##	 ""
##	    
##	query=Query(linguagem,query_ler)
##	cursor=QueryCursor(query)
##	matches=cursor.matches(tree.root_node)
##
##	vistos={}
##
##	if matches is not None:
##		for _,match in matches: 
##			str_node=match["str"][0]
##			linha=str_node.start_point.row
##			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode() 
##	   
##			if trecho in vistos:
##				continue
##			vistos[trecho]=linha
##	   
##		for codigo,row in vistos.items():
##			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="yellow")
##			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)
#
#
def Python(arquivo):
	
	Python1(arquivo)
#	Python2(arquivo)
#	Python_interpolationM(arquivo)
#	Python_interpolationB(arquivo)
#
#def Java(arquivo):
#	arquivo_b=arquivo.read_bytes()
#	linguagem=Language(java.language())
#	parser=Parser(linguagem)
#	tree=parser.parse(arquivo_b)
#	query_ler=""
#		(
#		  (binary_expression) @str
#		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
#		)
#	""
#	query=Query(linguagem,query_ler)
#	cursor=QueryCursor(query)
#	matches=cursor.matches(tree.root_node)
#
#	vistos={}
#
#	if matches is not None:
#		for _,match in matches:	
#			str_node=match["str"][0]
#			linha=str_node.start_point.row
#			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
#			
#			if trecho in vistos:
#				continue
#			vistos[trecho]=linha
#			
#		for codigo,row in vistos.items():
#			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="cyan")
#			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)
#
#def Php_simples(arquivo):
#	arquivo_b=arquivo.read_bytes()
#	linguagem=Language(php.language_php())
#	parser=Parser(linguagem)
#	tree=parser.parse(arquivo_b)
#	query_ler=""
#		(program
#		 (expression_statement 
#		  (assignment_expression
#		   left: (variable_name) @var
#		   right: [(encapsed_string) @str (binary_expression) @str]))
#		 
#		 (expression_statement
#		  (function_call_expression
#		  function: (name) @func
#		  arguments: (arguments
#		   (argument
#		   (variable_name) @arg))))
#		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
#		 (#eq? @func "mysqli_query")
#		 (#eq? @var @arg)
#		)
#	""
#	query=Query(linguagem,query_ler)
#	cursor=QueryCursor(query)
#	matches=cursor.matches(tree.root_node)
#
#	vistos={}
#
#	if matches is not None:
#		for _,match in matches:	
#			str_node=match["str"][0]
#			linha=str_node.start_point.row
#			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
#			
#			if trecho in vistos:
#				continue
#			vistos[trecho]=linha
#			
#		for codigo,row in vistos.items():
#			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="green")
#			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)
#
#def Php_attr(arquivo):
#	arquivo_b=arquivo.read_bytes()
#	linguagem=Language(php.language_php())
#	parser=Parser(linguagem)
#	tree=parser.parse(arquivo_b)
#	query_ler=""
#		(program
#		 (expression_statement 
#		  (assignment_expression
#		   left: (variable_name) @var
#		   right: [(encapsed_string) @str (binary_expression) @str]))
#		 
#		 (expression_statement
#		  (member_call_expression
#		  name: (name) @func
#		  arguments: (arguments
#		   (argument
#		   (variable_name) @arg))))
#		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
#	 	 (#match? @func "^(exec|prepare|query)$")
#		 (#eq? @var @arg)
#		)
#	""
#	query=Query(linguagem,query_ler)
#	cursor=QueryCursor(query)
#	matches=cursor.matches(tree.root_node)
#
#	vistos={}
#
#	if matches is not None:
#		for _,match in matches:	
#			str_node=match["str"][0]
#			linha=str_node.start_point.row
#			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
#			
#			if trecho in vistos:
#				continue
#			vistos[trecho]=linha
#			
#		for codigo,row in vistos.items():
#			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="green")
#			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)
#
#def Javascript(arquivo):
#	arquivo_b=arquivo.read_bytes()
#	linguagem=Language(js.language())
#	parser=Parser(linguagem)
#	tree=parser.parse(arquivo_b)
#	query_ler=""
#		(
#		 [
#		  (binary_expression) 
#		  (template_string)
#		 ]@str
#		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
#		)
#	""
#	query=Query(linguagem,query_ler)
#	cursor=QueryCursor(query)
#	matches=cursor.matches(tree.root_node)
#
#	vistos=set()
#
#	if matches is not None:
#		for _,match in matches:	
#			str_node=match["str"][0]
#			linha=str_node.start_point.row+1
#			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
#			
#			chave=(trecho,linha)
#			if chave in vistos:
#				continue
#			vistos.add(chave)
#			
#		for codigo,row in vistos:
#			
#			table1.add_row(arquivo.stem,str(arquivo),"Javascript",codigo,str(row),"SQL INJECTION","CRITICAL",style="red")
#			Salvar_db(arquivo.stem,str(arquivo),"Javascript",codigo,row,"SQL INJECTION",)

@app.command()
def scan(path: str = "."):
	pasta=Path(path)
	arquivos=list(pasta.rglob("*.py"))+list(pasta.rglob("*.js"))+list(pasta.rglob("*.java"))+list(pasta.rglob("*.php"))
	for arquivo in arquivos:
		if arquivo.suffix==".py":
			Python(arquivo)
#		elif arquivo.suffix==".java":
#			Java(arquivo)
#		elif arquivo.suffix==".php":
#			Php_attr(arquivo)
#			Php_simples(arquivo)
#		elif arquivo.suffix==".js":
#			Javascript(arquivo)
	if arquivo is not None:
		console.print(table)


@app.command()
def report_cmd(quantidade: int= tp.Option(None,"-q","-d","--quantidade")):
	db=sqlite3.connect(db_name)
	
	if quantidade is None:
		sql="select * from capturas"
		dados=db.execute(sql).fetchall()
	else:
		sql="select * from vulnerabilidades limit ?"
		dados=db.execute(sql,(quantidade,)).fetchall()

	for d in dados:
		if d[7]=="CRITICAL":
			cor="bold red"
		elif d[7]=="HIGH":
			cor="bold orange3"
		elif d[7]=="MEDIUM":
			cor="bold yellow"
		elif d[7]=="LOW":
			cor="bold green"
		table.add_row(d[1],d[2],d[3],str(d[4]),d[5],d[6],d[7],style=cor)
	console.print(table)

#
#@app.command()
#def report_pdf(quantidade: int= tp.Option(None,"-q","-d","--quantidade")):
#	db=sqlite3.connect(db_name)
#	
#	if quantidade is None:
#		sql="select * from capturas"
#		dados=db.execute(sql).fetchall()
#	else:
#		sql="select * from capturas limit ?"
#		dados=db.execute(sql,(quantidade,)).fetchall()
#
#	if dados is None:
#		raise tp.BadParameter("O banco de dados esta vazio")
#
#	pdf=FPDF()
#	pdf.add_page()
#	for d in dados:
#		if d[7]=="CRITICAL":
#			cor="bold red"
#		if d[7]=="HIGH":
#			cor="bold orange3"
#		if d[7]=="MEDIUM":
#			cor="bold yellow"
#		if d[7]=="LOW":
#			cor="bold green"
#		table.add_row(str(d[1],d[2],d[3],d[4],str(d[5]),d[6],d[7],d[8],style=cor)
#	console.print(table)
#
#
#@app.command()
#def report_json(quantidade: int= tp.Option(None,"-q","-d","--quantidade")):
#	db=sqlite3.connect(db_name)
#	
#	if quantidade is None:
#		sql="select * from capturas"
#		dados=db.execute(sql).fetchall()
#	else:
#		sql="select * from capturas limit ?"
#		dados=db.execute(sql,(quantidade,)).fetchall()
#
#	for d in dados:
#		if d[7]=="CRITICAL":
#			cor="bold red"
#		if d[7]=="HIGH":
#			cor="bold orange3"
#		if d[7]=="MEDIUM":
#			cor="bold yellow"
#		if d[7]=="LOW":
#			cor="bold green"
#		table2.add_row(str(d[1],d[2],d[3],d[4],str(d[5]),d[6],d[7],d[8],style=cor)
#	console.print(table2)
#
if __name__=="__main__":
	app()
