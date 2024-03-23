import requests
from faker import Faker
import random
import json

fake = Faker()


def generate_demo_student():
    student = {
        "username": fake.user_name(),
        "email": fake.email(),
        "password": fake.password(),
        "sex": random.choice(['male', 'female']),
        "phone_number": fake.phone_number(),
        "date_of_birth": fake.date_of_birth(minimum_age=18, maximum_age=25).strftime('%Y-%m-%d'),
        "address": fake.address(),
        "guardian_name": fake.name(),
        "guardian_phone": fake.phone_number(),
        "guardian_phone2": fake.phone_number(),
        "cohort": 1,
        "subject": [1, 2]
    }
    return student


def generate_demo_teacher():
    teacher = {
        "username": fake.user_name(),
        "email": fake.email(),
        "password": fake.password(),
        "sex": random.choice(['male', 'female']),
        "phone_number": fake.phone_number(),
        "date_of_birth": fake.date_of_birth(minimum_age=18, maximum_age=25).strftime('%Y-%m-%d'),
        "address": fake.address(),
        "subject": [1, 2]
    }
    return teacher


demo_students = [generate_demo_student() for _ in range(30)]
demo_teachers = [generate_demo_teacher() for _ in range(30)]

for demo_stu in demo_teachers:
    res = requests.post(
        'http://127.0.0.1:8000/api/teacher/create', json=demo_stu)
    print(res.status_code)
