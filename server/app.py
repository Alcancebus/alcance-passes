import os,csv
from io import StringIO
from datetime import datetime,date
from fastapi import FastAPI,Request,Form,HTTPException,UploadFile,File
from fastapi.responses import HTMLResponse,RedirectResponse,StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine,Column,Integer,String,DateTime,Boolean,ForeignKey
from sqlalchemy.orm import declarative_base,sessionmaker
from passlib.context import CryptContext
from pydantic import BaseModel

url=os.getenv("DATABASE_URL","sqlite:///./passes.db")
if url.startswith("postgres://"): url=url.replace("postgres://","postgresql+psycopg://",1)
elif url.startswith("postgresql://"): url=url.replace("postgresql://","postgresql+psycopg://",1)
engine=create_engine(url,connect_args={"check_same_thread":False} if url.startswith("sqlite") else {})
DB=sessionmaker(bind=engine); Base=declarative_base(); crypt=CryptContext(schemes=["bcrypt"],deprecated="auto")
app=FastAPI(title="Alcance Passes"); app.add_middleware(SessionMiddleware,secret_key=os.getenv("SESSION_SECRET","dev-secret"))
templates=Jinja2Templates(directory="templates"); DEVICE_TOKEN=os.getenv("DEVICE_TOKEN","DEMO-TOKEN")

class User(Base):
 __tablename__="users"; id=Column(Integer,primary_key=True); username=Column(String,unique=True); password_hash=Column(String); role=Column(String)
class Passenger(Base):
 __tablename__="passengers"; id=Column(Integer,primary_key=True); name=Column(String); pass_number=Column(String,unique=True); card_uid=Column(String,unique=True); valid_until=Column(String); active=Column(Boolean,default=True)
class Trip(Base):
 __tablename__="trips"; id=Column(Integer,primary_key=True); device=Column(String); line=Column(String); direction=Column(String); started_at=Column(DateTime,default=datetime.now); ended_at=Column(DateTime,nullable=True)
class HistoricalTrip(Base):
 __tablename__="historical_trips"
 id=Column(Integer,primary_key=True)
 started_at=Column(DateTime)
 line=Column(String)
 direction=Column(String)
 device=Column(String)
 passenger_count=Column(Integer)
 notes=Column(String,nullable=True)
 created_at=Column(DateTime,default=datetime.now)
class Validation(Base):
 __tablename__="validations"; id=Column(Integer,primary_key=True); trip_id=Column(Integer,ForeignKey("trips.id")); passenger_id=Column(Integer,ForeignKey("passengers.id"),nullable=True); card_uid=Column(String); result=Column(String); timestamp=Column(DateTime,default=datetime.now)
Base.metadata.create_all(engine)
def seed():
 d=DB()
 try:
  if d.query(User).count()==0:
   d.add_all([User(username="admin",password_hash=crypt.hash("admin123"),role="admin"),User(username="cim",password_hash=crypt.hash("cim123"),role="cim")]); d.commit()
 finally:d.close()
seed()
def ok(r,roles):
 u=r.session.get("u"); return u and u["role"] in roles
def tok(t):
 if t!=DEVICE_TOKEN: raise HTTPException(401,"Dispositivo não autorizado")

@app.get("/admin",response_class=HTMLResponse)
def admin(r:Request):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 d=DB()

 ps=d.query(Passenger).order_by(Passenger.name).all()

 historical=d.query(HistoricalTrip).order_by(
  HistoricalTrip.started_at.desc()
 ).all()

 d.close()

 return templates.TemplateResponse(
  "admin.html",
  {
   "request":r,
   "passengers":ps,
   "historical":historical
  }
 )
@app.post("/login")
def login(r:Request,username:str=Form(...),password:str=Form(...)):
 d=DB(); u=d.query(User).filter_by(username=username).first(); d.close()
 if not u or not crypt.verify(password,u.password_hash): return templates.TemplateResponse("login.html",{"request":r,"error":"Credenciais inválidas"},status_code=401)
 r.session["u"]={"username":u.username,"role":u.role}; return RedirectResponse("/admin" if u.role=="admin" else "/cim",303)
@app.get("/logout")
def logout(r:Request):r.session.clear();return RedirectResponse("/",303)
@app.post("/admin/change-password")
def change_admin_password(
 r:Request,
 current_password:str=Form(...),
 new_password:str=Form(...),
 confirm_password:str=Form(...)
):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 if new_password != confirm_password:
  return RedirectResponse("/admin?password_error=confirm",303)

 if len(new_password) < 10:
  return RedirectResponse("/admin?password_error=short",303)

 d=DB()

 try:
  username=r.session["u"]["username"]
  u=d.query(User).filter_by(username=username).first()

  if not u or not crypt.verify(current_password,u.password_hash):
   return RedirectResponse("/admin?password_error=current",303)

  u.password_hash=crypt.hash(new_password)
  d.commit()

 finally:
  d.close()

 return RedirectResponse("/admin?password_changed=1",303)
@app.get("/admin",response_class=HTMLResponse)
def admin(r:Request):
 if not ok(r,["admin"]):return RedirectResponse("/",303)
 d=DB(); ps=d.query(Passenger).order_by(Passenger.name).all(); d.close()
 return templates.TemplateResponse("admin.html",{"request":r,"passengers":ps})
@app.post("/admin/passenger")
def add(r:Request,name:str=Form(...),pass_number:str=Form(...),card_uid:str=Form(...),valid_until:str=Form(...)):
 if not ok(r,["admin"]):return RedirectResponse("/",303)
 d=DB(); d.add(Passenger(name=name,pass_number=pass_number,card_uid=card_uid.upper(),valid_until=valid_until)); d.commit(); d.close();return RedirectResponse("/admin",303)
@app.post("/admin/passenger/{pid}/edit")
def edit_passenger(
 pid:int,
 r:Request,
 name:str=Form(...),
 pass_number:str=Form(...),
 card_uid:str=Form(...),
 valid_until:str=Form(...)
):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 d=DB()
 p=d.get(Passenger,pid)

 if p:
  p.name=name.strip()
  p.pass_number=pass_number.strip()
  p.card_uid=card_uid.strip().upper()
  p.valid_until=valid_until
  d.commit()

 d.close()
 return RedirectResponse("/admin",303)
@app.post("/admin/passenger/{pid}/toggle")
def toggle_passenger(pid:int,r:Request):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 d=DB()
 p=d.get(Passenger,pid)

 if p:
  p.active=not p.active
  d.commit()

 d.close()
 return RedirectResponse("/admin",303)

@app.post("/admin/passenger/{pid}/delete")
def delete_passenger(pid:int,r:Request):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 d=DB()
 p=d.get(Passenger,pid)

 if p:
  # Mantém as validações antigas, mas deixa de as ligar
  # ao passe que está a ser eliminado.
  d.query(Validation).filter(
   Validation.passenger_id==pid
  ).update(
   {Validation.passenger_id:None},
   synchronize_session=False
  )

  d.delete(p)
  d.commit()

 d.close()
 return RedirectResponse("/admin",303)
@app.post("/admin/historical-trip")
def add_historical_trip(
 r:Request,
 trip_date:str=Form(...),
 trip_time:str=Form(...),
 line:str=Form(...),
 direction:str=Form(...),
 device:str=Form(...),
 passenger_count:int=Form(...),
 notes:str=Form("")
):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 started=datetime.strptime(
  trip_date+" "+trip_time,
  "%Y-%m-%d %H:%M"
 )

 d=DB()
 d.add(HistoricalTrip(
  started_at=started,
  line=line,
  direction=direction,
  device=device,
  passenger_count=passenger_count,
  notes=notes
 ))
 d.commit()
 d.close()

 return RedirectResponse("/admin",303)
 
@app.post("/admin/historical-trip/{hid}/edit")
def edit_historical_trip(
 hid:int,
 r:Request,
 trip_date:str=Form(...),
 trip_time:str=Form(...),
 line:str=Form(...),
 direction:str=Form(...),
 device:str=Form(...),
 passenger_count:int=Form(...),
 notes:str=Form("")
):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 d=DB()
 h=d.get(HistoricalTrip,hid)

 if h:
  h.started_at=datetime.strptime(
   trip_date+" "+trip_time,
   "%Y-%m-%d %H:%M"
  )
  h.line=line
  h.direction=direction
  h.device=device
  h.passenger_count=passenger_count
  h.notes=notes
  d.commit()

 d.close()
 return RedirectResponse("/admin",303)


@app.post("/admin/historical-trip/{hid}/delete")
def delete_historical_trip(hid:int,r:Request):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 d=DB()
 h=d.get(HistoricalTrip,hid)

 if h:
  d.delete(h)
  d.commit()

 d.close()
 return RedirectResponse("/admin",303)
@app.post("/admin/historical-trip/import")
async def import_historical_trips(
 r:Request,
 file:UploadFile=File(...)
):
 if not ok(r,["admin"]):
  return RedirectResponse("/",303)

 try:
  raw=await file.read()

  # Aceita CSV UTF-8 normal e ficheiros exportados pelo Excel
  try:
   text=raw.decode("utf-8-sig")
  except UnicodeDecodeError:
   text=raw.decode("cp1252")

  reader=csv.DictReader(StringIO(text),delimiter=";")

  required={
   "Data",
   "Hora",
   "Linha",
   "Sentido",
   "Autocarro",
   "Passageiros"
  }

  if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
   raise HTTPException(
    400,
    "CSV inválido. Colunas obrigatórias: Data;Hora;Linha;Sentido;Autocarro;Passageiros"
   )

  d=DB()
  imported=0

  try:
   for row in reader:

    # Ignorar linhas completamente vazias
    if not any((v or "").strip() for v in row.values()):
     continue

    started=datetime.strptime(
     row["Data"].strip()+" "+row["Hora"].strip(),
     "%Y-%m-%d %H:%M"
    )

    line=row["Linha"].strip()
    direction=row["Sentido"].strip()
    device=row["Autocarro"].strip()
    passenger_count=int(row["Passageiros"].strip())
    notes=(row.get("Observação") or "").strip()

    if passenger_count < 0:
     raise ValueError("Número de passageiros inválido")

    # Evita importar novamente a mesma viagem
    exists=d.query(HistoricalTrip).filter(
     HistoricalTrip.started_at==started,
     HistoricalTrip.line==line,
     HistoricalTrip.direction==direction,
     HistoricalTrip.device==device
    ).first()

    if exists:
     continue

    d.add(HistoricalTrip(
     started_at=started,
     line=line,
     direction=direction,
     device=device,
     passenger_count=passenger_count,
     notes=notes
    ))

    imported+=1

   d.commit()

  except:
   d.rollback()
   raise

  finally:
   d.close()

  return RedirectResponse(
   f"/admin?imported={imported}",
   303
  )

 except HTTPException:
  raise

 except Exception as e:
  raise HTTPException(
   400,
   "Erro ao importar CSV: "+str(e)
  )

class Start(BaseModel):device:str;line:str;direction:str;token:str
class Read(BaseModel):trip_id:int;card_uid:str;token:str
class End(BaseModel):trip_id:int;token:str

@app.post("/api/trip/start")
def start(x:Start):
 tok(x.token);d=DB();t=Trip(device=x.device,line=x.line,direction=x.direction);d.add(t);d.commit();d.refresh(t);i=t.id;d.close();return{"trip_id":i}
@app.post("/api/validate")
def validate(x:Read):
 tok(x.token);d=DB();t=d.get(Trip,x.trip_id)
 if not t or t.ended_at:d.close();raise HTTPException(400,"Viagem inválida")
 uid=x.card_uid.upper();p=d.query(Passenger).filter_by(card_uid=uid).first()
 result="SEM PASSE" if not p else ("BLOQUEADO" if not p.active else ("EXPIRADO" if p.valid_until<date.today().isoformat() else "VALIDO"))
 # duplicate same card on same trip: report it, don't add another validation
 previous=d.query(Validation).filter_by(trip_id=t.id,card_uid=uid,result="VALIDO").first()
 if previous and result=="VALIDO":
  out={"result":"JA_LIDO","name":p.name,"pass_number":p.pass_number,"time":previous.timestamp.strftime("%H:%M")};d.close();return out
 v=Validation(trip_id=t.id,passenger_id=p.id if p else None,card_uid=uid,result=result);d.add(v);d.commit()
 out={"result":result,"name":p.name if p else "","pass_number":p.pass_number if p else "","time":v.timestamp.strftime("%H:%M")};d.close();return out
@app.get("/api/trip/{tid}/passengers")
def passengers(tid:int,token_value:str):
 tok(token_value);d=DB();rows=d.query(Validation,Passenger).outerjoin(Passenger,Validation.passenger_id==Passenger.id).filter(Validation.trip_id==tid).order_by(Validation.timestamp).all()
 out=[{"name":p.name if p else "","pass_number":p.pass_number if p else "","result":v.result,"time":v.timestamp.strftime("%H:%M")} for v,p in rows];d.close();return out
@app.post("/api/trip/end")
def end(x:End):
 tok(x.token);d=DB();t=d.get(Trip,x.trip_id)
 if t:t.ended_at=datetime.now();d.commit()
 d.close();return{"ok":True}

@app.get("/cim",response_class=HTMLResponse)
def cim(r:Request,month:str|None=None):
 if not ok(r,["admin","cim"]):
  return RedirectResponse("/",303)

 month=month or date.today().strftime("%Y-%m")
 d=DB()

 # Viagens realizadas com validação NFC
 trips=[
  t for t in d.query(Trip).order_by(Trip.started_at.desc()).all()
  if t.started_at.strftime("%Y-%m")==month
 ]

 data=[]

 for t in trips:
  n=d.query(Validation).filter_by(
   trip_id=t.id,
   result="VALIDO"
  ).count()

  data.append({
   "id":t.id,
   "started_at":t.started_at,
   "line":t.line,
   "direction":t.direction,
   "device":t.device,
   "passengers":n,
   "type":"NFC"
  })

 # Viagens históricas introduzidas manualmente
 historical=[
  h for h in d.query(HistoricalTrip).order_by(
   HistoricalTrip.started_at.desc()
  ).all()
  if h.started_at.strftime("%Y-%m")==month
 ]

 for h in historical:
  data.append({
   "id":h.id,
   "started_at":h.started_at,
   "line":h.line,
   "direction":h.direction,
   "device":h.device,
   "passengers":h.passenger_count,
   "type":"HISTORICO"
  })

 # Juntar tudo por ordem cronológica
 data.sort(
  key=lambda x:x["started_at"],
  reverse=True
 )

 d.close()

 return templates.TemplateResponse(
  "cim.html",
  {
   "request":r,
   "month":month,
   "data":data
  }
 )
@app.get("/cim/trip/{tid}",response_class=HTMLResponse)
def detail(tid:int,r:Request):
 if not ok(r,["admin","cim"]):return RedirectResponse("/",303)
 d=DB();t=d.get(Trip,tid);rows=d.query(Validation,Passenger).outerjoin(Passenger,Validation.passenger_id==Passenger.id).filter(Validation.trip_id==tid).order_by(Validation.timestamp).all();d.close()
 return templates.TemplateResponse("trip.html",{"request":r,"trip":t,"rows":rows})
@app.get("/cim/export.csv")
def export(r:Request,month:str):
 if not ok(r,["admin","cim"]):
  return RedirectResponse("/",303)

 d=DB()
 s=StringIO()
 w=csv.writer(s,delimiter=";")

 w.writerow([
  "Data",
  "Hora",
  "Linha",
  "Sentido",
  "Autocarro",
  "Nome",
  "Passe",
  "Estado",
  "Origem",
  "Total passageiros",
  "Observação"
 ])

 # VIAGENS NFC
 trips=[
  t for t in d.query(Trip).order_by(Trip.started_at).all()
  if t.started_at.strftime("%Y-%m")==month
 ]

 for t in trips:
  rows=d.query(Validation,Passenger).outerjoin(
   Passenger,
   Validation.passenger_id==Passenger.id
  ).filter(
   Validation.trip_id==t.id
  ).order_by(
   Validation.timestamp
  ).all()

  valid_count=sum(
   1 for v,p in rows if v.result=="VALIDO"
  )

  for v,p in rows:
   w.writerow([
    t.started_at.strftime("%Y-%m-%d"),
    v.timestamp.strftime("%H:%M:%S"),
    t.line,
    t.direction,
    t.device,
    p.name if p else "",
    p.pass_number if p else "",
    v.result,
    "NFC",
    valid_count,
    ""
   ])

 # VIAGENS HISTÓRICAS
 historical=[
  h for h in d.query(HistoricalTrip).order_by(
   HistoricalTrip.started_at
  ).all()
  if h.started_at.strftime("%Y-%m")==month
 ]

 for h in historical:
  w.writerow([
   h.started_at.strftime("%Y-%m-%d"),
   h.started_at.strftime("%H:%M:%S"),
   h.line,
   h.direction,
   h.device,
   "",
   "",
   "REGISTO HISTÓRICO",
   "Manual / Histórico",
   h.passenger_count,
   h.notes or ""
  ])

 d.close()

 content="\ufeff"+s.getvalue()

 return StreamingResponse(
  iter([content]),
  media_type="text/csv; charset=utf-8",
  headers={
   "Content-Disposition":
   f'attachment; filename="cim_{month}.csv"'
  }
 )
