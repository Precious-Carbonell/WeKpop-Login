import customtkinter
import sqlite3
import bcrypt
from tkinter import *
from tkinter import ttk, messagebox  # Add import for ttk module

app = customtkinter.CTk()
app.title('Login')
app.geometry('450x360')
app.config(bg='#001220')

font1 = ('Helvetica', 25, 'bold')
font2 = ('Arial', 17, 'bold')
font3 = ('Arial', 13, 'bold')
font4 = ('Arial', 13, 'bold', 'underline')

conn = sqlite3.connect('data.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        username TEXT NOT NULL,
        password TEXT NOT NULL)''')

def signup():
    username = username_entry.get()
    password = password_entry.get()
    if username != '' and password != '':
        cursor.execute('SELECT username FROM users WHERE username = ?', [username])
        if cursor.fetchone() is not None:
            messagebox.showerror('Error', 'Username already exists')
        else:
            encoded_password = password.encode('utf-8')
            hashed_password = bcrypt.hashpw(encoded_password, bcrypt.gensalt())
            cursor.execute('INSERT INTO users VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            messagebox.showinfo('Success', 'Account created successfully.')
    else:
        messagebox.showerror('Error', 'Enter all data.')

def login_account():
    global username_entry, password_entry  # Accessing global variables

    username = username_entry.get()
    password = password_entry.get()
    if username != '' and password != '':
        cursor.execute('SELECT password FROM users WHERE username = ?', [username])
        result = cursor.fetchone()
        if result:
            if bcrypt.checkpw(password.encode('utf-8'), result[0]):
                if username == 'admin' and password == '12345':
                    messagebox.showinfo('Success', 'Login successful.')
                    show_user_details_window()
                else:
                    messagebox.showinfo('Success', 'Login successful.')
            else: 
                messagebox.showerror('Error', 'Invalid password.')
        else:
            messagebox.showerror('Error', 'Invalid username.')
    else:
        messagebox.showerror('Error', 'Enter all data.')

def show_user_details_window():
    details_window = Toplevel(app)
    details_window.title("User Details")
    details_window.geometry("600x400")

    # Fetch user details from the database
    cursor.execute('SELECT rowid, username, password FROM users')
    users = cursor.fetchall()

    # Create a treeview to display the user details
    tree = ttk.Treeview(details_window, columns=("ID", "Username", "Password"), selectmode="extended")
    tree.heading('#0', text='ID')
    tree.heading('#1', text='Username')
    tree.heading('#2', text='Password')

    # Insert user details into the treeview
    for user in users:
        tree.insert("", "end", text=user[0], values=(user[1], user[2]))

    tree.pack(expand=YES, fill=BOTH)

    # Button to edit selected user
    edit_button = Button(details_window, text="Edit User", command=lambda: edit_user(tree))
    edit_button.pack()

    # Button to delete selected user
    delete_button = Button(details_window, text="Delete User", command=lambda: delete_user(tree))
    delete_button.pack()

def edit_user(tree):
    # Fetch selected item from the treeview
    selected_item = tree.selection()
    if selected_item:
        # Fetch details of the selected user
        item = tree.item(selected_item)
        user_id = item['text']
        username = item['values'][0]
        password = item['values'][1]

        # Create a popup window for editing user
        edit_window = Toplevel()
        edit_window.title("Edit User")
        edit_window.geometry("300x200")

        # Labels and entry widgets for editing
        username_label = Label(edit_window, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=5)
        username_entry = Entry(edit_window)
        username_entry.insert(0, username)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        password_label = Label(edit_window, text="Password:")
        password_label.grid(row=1, column=0, padx=10, pady=5)
        password_entry = Entry(edit_window)
        password_entry.insert(0, password)
        password_entry.grid(row=1, column=1, padx=10, pady=5)

        # Button to save changes
        save_button = Button(edit_window, text="Save Changes", command=lambda: save_changes(tree, user_id, username_entry.get(), password_entry.get()))
        save_button.grid(row=2, columnspan=2, pady=10)

def save_changes(tree, user_id, new_username, new_password):
    # Update user details in the database
    cursor.execute("UPDATE users SET username=?, password=? WHERE rowid=?", (new_username, new_password, user_id))
    conn.commit()

    # Update details in the treeview
    item = tree.selection()[0]
    tree.item(item, values=(new_username, new_password))

def delete_user(tree):
    # Get selected item from the treeview
    selected_item = tree.selection()
    if selected_item:
        for item in selected_item:
            # Remove selected item from the treeview
            tree.delete(item)
            # Delete corresponding entry from the database
            cursor.execute("DELETE FROM users WHERE rowid=?", (item,))
            conn.commit()

def login():
    frame1.destroy()
    frame2 = customtkinter.CTkFrame(app, bg_color='#001220', fg_color='#001220', width=470, height=360)
    frame2.place(x=0, y=0)

    image1 = PhotoImage(file="1.png")
    image1_label = Label(frame2, image=image1, bg='#001220')
    image1_label.place (x=0, y=0)
    frame2.image1 = image1

    global username_entry, password_entry  # Accessing global variables

    username_entry = customtkinter.CTkEntry(frame2, font=font2, text_color= '#FFFFFF', fg_color='#001a2e', bg_color='#121111', border_color= '#004780', border_width= 3, placeholder_text='Username', placeholder_text_color='#a3a3a3', width= 200, height= 50)
    username_entry.place(x=230, y=80)

    password_entry = customtkinter.CTkEntry(frame2, font=font2, show= '*', text_color= '#FFFFFF', fg_color='#001a2e', bg_color='#121111', border_color= '#004780', border_width= 3, placeholder_text='Password', placeholder_text_color='#a3a3a3', width= 200, height= 50)
    password_entry.place(x=230, y=150)

    login_button2 = customtkinter.CTkButton(frame2, command=login_account, font=font2, text_color= '#FFFFFF', text= 'Login', fg_color='#00965d', hover_color='#006e44', bg_color= '#121111', cursor='hand2', corner_radius=5, width= 120)
    login_button2.place(x=230, y=220)

frame1 = customtkinter.CTkFrame(app, bg_color='#001220', fg_color='#001220', width=470, height=360)
frame1.place(x=0, y=0)

image1 = PhotoImage(file="1.png")
image1_label = Label(frame1, image=image1, bg='#001220')
image1_label.place (x=0, y=0)

signup_label = customtkinter.CTkLabel(frame1, text="Sign Up", font=font1, text_color='#FFFFFF', bg_color='#001220')
signup_label.place(x=280, y=20)

username_entry = customtkinter.CTkEntry(frame1, font=font2, text_color= '#FFFFFF', fg_color='#001a2e', bg_color='#121111', border_color= '#004780', border_width= 3, placeholder_text='Username', placeholder_text_color='#a3a3a3', width= 200, height= 50)
username_entry.place(x=230, y=80)

password_entry = customtkinter.CTkEntry(frame1, font=font2, show= '*', text_color= '#FFFFFF', fg_color='#001a2e', bg_color='#121111', border_color= '#004780', border_width= 3, placeholder_text='Password', placeholder_text_color='#a3a3a3', width= 200, height= 50)
password_entry.place(x=230, y=150)

signup_button = customtkinter.CTkButton(frame1, command=signup,font=font2, text_color= '#FFFFFF', text= 'Sign up', fg_color='#00965d', hover_color='#006e44', bg_color= '#121111', cursor='hand2', corner_radius=5, width= 120)
signup_button.place(x=230, y=220)

login_label = customtkinter.CTkLabel(frame1, font=font3, text= 'Already have an account?', text_color='#FFFFFF', bg_color='#001220')
login_label.place(x=230, y=250)

login_button = customtkinter.CTkButton(frame1, command=login, font=font4, text_color= '#00bf77', text= 'Login', fg_color='#001220', hover_color='#001220', cursor='hand2', width=40)
login_button.place(x=395, y=250)

app.mainloop()
