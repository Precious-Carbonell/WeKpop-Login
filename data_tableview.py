import sqlite3
from tkinter import Tk, ttk, Button

conn = sqlite3.connect('data.db')
cursor = conn.cursor()

def display_users():
    display_window = Tk()
    display_window.title('Users Table')
    display_window.geometry('600x400')

    tree = ttk.Treeview(display_window)
    tree["columns"] = ("username", "password")
    tree.column("#0", width=0, stretch='NO')
    tree.column("username", anchor='w', width=150)
    tree.column("password", anchor='w', width=150)
    tree.heading("username", text="Username")
    tree.heading("password", text="Password")

    cursor.execute('SELECT * FROM users')
    rows = cursor.fetchall()
    for row in rows:
        tree.insert("", "end", values=row)

    tree.pack(expand=True, fill='both')

    # Function to delete selected user
    def delete_user():
        selected_item = tree.selection()[0]
        username = tree.item(selected_item, "values")[0]
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        tree.delete(selected_item)

    # Button to delete selected user
    delete_button = Button(display_window, text="Delete User", command=delete_user)
    delete_button.pack()

    display_window.mainloop()

if __name__ == "__main__":
    display_users()
