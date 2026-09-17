from rich.console import Console
from rich.table import Table
from pydantic import BaseModel,Field
from tree_sitter import Language,Parser,QueryCursor,Query
from loguru import logger as lg
from datetime import datetime
import tree_sitter_python as py
import tree_sitter_php as php
import tree_sitter_java as java
import tree_sitter_javascript as js
import typer as tp
import sqlite3
import json
import sys

app=tp.Typer()
lg.remove()
lg.add(sys.stdout,format="<level>{level}</level> | {message}")
lg.add("sqli.log",rotation="500 MB",retention="14 days",level="DEBUG")
db_name="sql_injection.db"
json_name="relatorio_sqli.json"

print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
def Dados(BaseModel):
	nome: str
	origem: str
	codigo: str

def Criar_db():
	db=sqlite3.connect(db_name)
	sql="""
		create table if not exists capturas(
			id integer primary key autoincrement,nome_arquivo text,origem_vuln text,trecho_codigo text,
			data datetime)
	""" 
	db.execute(sql)
	db.commit()
	db.close()
Criar_db()

def Salvar_db(dados: Dados):
	db=sqlite3.connect(db_name)
	sql="""
		insert into capturas values(?,?,?,datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
	"""
	db.execute(sql,(dados.nome,dados.origem,dados.codigo))
	db.commit()
	db.close()

