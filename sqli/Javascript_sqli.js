const id=req.query.id
const query="select * from users where  id='"+id+"'"
db.query(query)

const query2=`select * from users where id='{id}'`
connection.query(query2)
