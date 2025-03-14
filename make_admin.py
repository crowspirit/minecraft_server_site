from app import app, db, User

def make_admin(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            db.session.commit()
            print(f"Користувача {username} зроблено адміністратором!")
        else:
            print(f"Користувача {username} не знайдено")

def remove_admin(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = False
            db.session.commit()
            print(f"У користувача {username} забрано права адміністратора!")
        else:
            print(f"Користувача {username} не знайдено")

def list_admins():
    with app.app_context():
        admins = User.query.filter_by(is_admin=True).all()
        if admins:
            print("\nСписок адміністраторів:")
            for admin in admins:
                print(f"- {admin.username}")
        else:
            print("Адміністраторів не знайдено")

if __name__ == "__main__":
    while True:
        print("\nКерування адміністраторами:")
        print("1. Зробити користувача адміністратором")
        print("2. Забрати права адміністратора")
        print("3. Показати список адміністраторів")
        print("4. Вийти")
        
        choice = input("\nВиберіть опцію (1-4): ")
        
        if choice == "1":
            username = input("Введіть ім'я користувача: ")
            make_admin(username)
        elif choice == "2":
            username = input("Введіть ім'я користувача: ")
            remove_admin(username)
        elif choice == "3":
            list_admins()
        elif choice == "4":
            print("До побачення!")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.") 