from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import random
from string import ascii_uppercase
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
app.config["SECRET_KEY"] = "hdgfsugreuf"
socketio = SocketIO(app)

rooms = {}

ENCRYPTION_KEY = get_random_bytes(16)

def encrypt_message(message):
    """Encrypts the message using AES."""
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(encrypted_message):
    """Decrypts the message using AES."""
    data = base64.b64decode(encrypted_message)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

@app.route("/", methods=["POST", "GET"])
def home():
    session.clear()
    if request.method == "POST":
        name = request.form.get("name") 
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template("home.html", error="Please enter your NAME", code=code, name=name)
        if join!=False and not code:
            return render_template("home.html", error="Please enter the CODE", code=code, name=name)
        
        room = code
        if create!=False:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": []}
        elif code not in rooms:
            return render_template("home.html", error="Anonymous Error (Room doesn't exist)", code=code, name=name)
        
        session["room"] = room
        session["name"] = name  
        return redirect(url_for("room"))
    
    return render_template("home.html")
    
def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code +=random.choice(ascii_uppercase)
        if code not in rooms:
            break
    return code

@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))
    return render_template("room.html", code=room)

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return
    content = {
        "name": session.get("name"), 
        "message": decrypt_message(encrypt_message(data['data']))
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {encrypt_message(data['data'])}")  

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name") 
    if not room or not name:
        return 
    if room not in rooms:
        leave_room(room)
        return
    join_room(room)
    send({"name": name, "message": "has entered"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    if name is not None: 
        send({"name": name, "message": "has left"}, to=room)
        print(f"{name} has left room {room}")

if __name__ == "__main__":
    socketio.run(app, debug=True)
