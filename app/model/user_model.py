from mongoengine import *


class User(Document):

    id = StringField()
    name = StringField(required=True)
    lastname = StringField(required=True)
    email = StringField(required=True)
    password = StringField(required=True)
    enabled = BooleanField(required=True)
    google = BooleanField(required=True)
    dateInit = DateField(required=True)
    dateLogin = DateField(required=True)
    admin = BooleanField(required=True)
    image = ImageField(required=False)

    def __init__(
        self,
        name,
        lastname,
        email,
        password,
        enabled,
        google,
        dateInit,
        dateLogin,
        admin,
        *args,
        **values
    ):
        super().__init__(*args, **values)
        self.name = name
        self.lastname = lastname
        self.email = email
        self.password = password
        self.enabled = enabled
        self.google = google
        self.dateInit = dateInit
        self.dateLogin = dateLogin
        self.admin = admin
