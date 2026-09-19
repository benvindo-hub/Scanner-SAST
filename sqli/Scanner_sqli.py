from rich.console import Console
from rich.table import Table
from tree_sitter import Language,Parser,QueryCursor,Query
from datetime import datetime
from pathlib import Path
import tree_sitter_python as py
import tree_sitter_php as php
import tree_sitter_java as java
import tree_sitter_javascript as js
import typer as tp
import sqlite3
import json

app=tp.Typer()

console=Console()
table1=Table()
table1.add_column("[white]Nome do arquivo[/white]")
table1.add_column("[white]Tipo[/white]")
table1.add_column("[white]Origem[/white]")
table1.add_column("[white]Codigo vulneravel[/white]")
table1.add_column("[white]Linha[/white]")

table2=Table()
table2.add_column("[white]ID[/white]")
table2.add_column("[white]Nome do arquivo[/white]")
table2.add_column("[white]Tipo[/white]")
table2.add_column("[white]Origem[/white]")
table2.add_column("[white]Codigo vulneravel[/white]")
table2.add_column("[white]Linha[/white]")
table2.add_column("[white]Data[/white]")

db_name="sql_injection.db"
json_name="relatorio_sqli.json"

def Criar_db():
	db=sqlite3.connect(db_name)
	sql="""
		create table if not exists capturas(
			id integer primary key autoincrement,nome_arquivo text,tipo text,origem text,codigo_vuln text,
			linha_codigo integer,data datetime)
	""" 
	db.execute(sql)
	db.commit()
	db.close()
Criar_db()

def Salvar_db(nome: str,tipo: str,origem: str,codigo: str,linha: int):
	db=sqlite3.connect(db_name)
	sql="""
		insert into capturas (nome_arquivo,tipo,origem,codigo_vuln,linha_codigo,data) values (?,?,?,?,?,?)
	"""
	db.execute(sql,(nome,tipo,origem,codigo,linha,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
	db.commit()
	db.close()

def Python(arquivo):
	arquivo_b=arquivo.read_bytes()
	linguagem=Language(py.language())
	parser=Parser(linguagem)
	tree=parser.parse(arquivo_b)
	query_ler="""
		(
		 [
		  (binary_operator) 
		  (string (interpolation))
		 ]@str
		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
		)
	"""
	query=Query(linguagem,query_ler)
	cursor=QueryCursor(query)
	matches=cursor.matches(tree.root_node)

	vistos={}

	if matches is not None:
		for _,match in matches:	
			str_node=match["str"][0]
			linha=str_node.start_point.row
			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
			
			if trecho in vistos:
				continue
			vistos[trecho]=linha
			
		for codigo,row in vistos.items():
			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="yellow")
			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)

def Java(arquivo):
	arquivo_b=arquivo.read_bytes()
	linguagem=Language(java.language())
	parser=Parser(linguagem)
	tree=parser.parse(arquivo_b)
	query_ler="""
		(
		  (binary_expression) @str
		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
		)
	"""
	query=Query(linguagem,query_ler)
	cursor=QueryCursor(query)
	matches=cursor.matches(tree.root_node)

	vistos={}

	if matches is not None:
		for _,match in matches:	
			str_node=match["str"][0]
			linha=str_node.start_point.row
			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
			
			if trecho in vistos:
				continue
			vistos[trecho]=linha
			
		for codigo,row in vistos.items():
			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="cyan")
			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)

def Php(arquivo):
	arquivo_b=arquivo.read_bytes()
	linguagem=Language(php.language_php())
	parser=Parser(linguagem)
	tree=parser.parse(arquivo_b)
	query_ler="""
		(
		  (encapsed_string) @str
		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
		)
	"""
	query=Query(linguagem,query_ler)
	cursor=QueryCursor(query)
	matches=cursor.matches(tree.root_node)

	vistos={}

	if matches is not None:
		for _,match in matches:	
			str_node=match["str"][0]
			linha=str_node.start_point.row
			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
			
			if trecho in vistos:
				continue
			vistos[trecho]=linha
			
		for codigo,row in vistos.items():
			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="green")
			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)

def Javascript(arquivo):
	arquivo_b=arquivo.read_bytes()
	linguagem=Language(js.language())
	parser=Parser(linguagem)
	tree=parser.parse(arquivo_b)
	query_ler="""
		(
		 [
		  (binary_expression) 
		  (template_string)
		 ]@str
		 (#match? @str "(?i)\\\\b(select|update|insert)\\\\b")
		)
	"""
	query=Query(linguagem,query_ler)
	cursor=QueryCursor(query)
	matches=cursor.matches(tree.root_node)

	vistos={}

	if matches is not None:
		for _,match in matches:	
			str_node=match["str"][0]
			linha=str_node.start_point.row
			trecho=arquivo_b.split(b'\n')[str_node.start_point.row].decode()	
			
			if trecho in vistos:
				continue
			vistos[trecho]=linha
			
		for codigo,row in vistos.items():
			table1.add_row(arquivo.stem,arquivo.suffix,str(arquivo),codigo,str(row),style="red")
			Salvar_db(arquivo.stem,arquivo.suffix,str(arquivo),codigo,row)

#lg.catch
@app.command()
def main():
	pasta=Path(".")
	arquivos=list(pasta.rglob("*.py"))+list(pasta.rglob("*.js"))+list(pasta.rglob("*.java"))+list(pasta.rglob("*.php"))
	for arquivo in arquivos:
		if arquivo.suffix==".py":
			Python(arquivo)
		elif arquivo.suffix==".java":
			Java(arquivo)
		elif arquivo.suffix==".php":
			Php(arquivo)
		elif arquivo.suffix==".js":
			Javascript(arquivo)
	console.print(table1)


@app.command()
def Consulta_geral(quantidade: int= tp.Option(None,"-q","--quantidade")):
	db=sqlite3.connect(db_name)
	
	if quantidade is None:
		sql="select * from capturas"
		dados=db.execute(sql).fetchall()
	else:
		sql="select * from capturas limit ?"
		dados=db.execute(sql,(quantidade,)).fetchall()

	for d in dados:
		if d[2]==".py":
			cor="yellow"
		if d[2]==".java":
			cor="cyan"
		if d[2]==".php":
			cor="green"
		if d[2]==".js":
			cor="red"
		table2.add_row(str(d[0]),d[1],d[2],d[3],d[4],str(d[5]),d[6],style=cor)
	console.print(table2)

if __name__=="__main__":
	app()
