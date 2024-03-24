import secrets
from django.db import models
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.core.exceptions import PermissionDenied
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import AbstractUser, PermissionsMixin, Permission, Group
from django.forms import ValidationError
from django.db.models.signals import post_migrate

# Create your models here.

# ===================================================== Main models


class School(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    short_name = models.CharField(max_length=20, default='')
    location = models.CharField(max_length=255)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)


class Course(models.Model):
    id = models.AutoField(primary_key=True)
    course_name = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    def __str__(self) -> str:
        return self.course_name


class Subject(models.Model):
    id = models.AutoField(primary_key=True)
    subject_name = models.CharField(max_length=255)
    book_name = models.CharField(max_length=255)
    price = models.IntegerField(default=0)

    course = models.ForeignKey(
        Course, on_delete=models.DO_NOTHING, default='')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self) -> str:
        return self.subject_name

    def get_course_name(self):
        return self.course.course_name

    def get_price(self):
        return self.price


class Cohort(models.Model):
    id = models.AutoField(primary_key=True)
    cohort_name = models.CharField(max_length=255)

    course = models.ForeignKey(
        Course, on_delete=models.CASCADE, related_name='cohorts')

    session_start_date = models.DateField(null=True, blank=True)
    session_end_date = models.DateField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = models.Manager()

    def __str__(self) -> str:
        return f"{self.cohort_name} - {self.course.course_name}"

    def get_course_name(self):
        return self.course.course_name


class Invoice(models.Model):
    file = models.FileField(upload_to='invoices/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.file.name


class EmailCredentials(models.Model):
    email = models.EmailField(
        max_length=255, null=False, blank=False, unique=True)
    password = models.CharField(max_length=255)

    def __str__(self) -> str:
        return self.email


class EmailTemplates(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    message = models.TextField(null=False)
    objects = models.Manager()

    def __str__(self) -> str:
        return self.title


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, user_type=None, **extra_fields):
        """ Create and return a regular user with an email and password. """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        if user_type is None:
            user_type = CustomUser.STUDENT
        extra_fields = self.check_type(user_type, **extra_fields)
        extra_fields.setdefault('user_type', user_type)
        extra_fields.setdefault('is_active', True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        print(f"Created user for this email: {email}")
        return user

    def check_type(self, user_type, **extra_fields):
        if user_type == CustomUser.ADMIN:
            extra_fields.setdefault('is_superuser', True)
            extra_fields.setdefault('is_staff', True)
        elif user_type == CustomUser.TEACHER:
            extra_fields.setdefault('is_superuser', False)
            extra_fields.setdefault('is_staff', True)
        elif user_type == CustomUser.STUDENT:
            extra_fields.setdefault('is_superuser', False)
            extra_fields.setdefault('is_staff', False)

        return extra_fields

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('user_type', CustomUser.ADMIN)
        return self.create_user(email, password, **extra_fields)

    def check_user(self, email):
        user = not CustomUser.objects.filter(email=email).exists()
        return user


class CustomUser(AbstractUser, PermissionsMixin):
    STUDENT = 'student'
    TEACHER = 'teacher'
    ADMIN = 'admin'

    USER_TYPES = [
        (STUDENT, 'Student'),
        (TEACHER, 'Teacher'),
        (ADMIN, 'Admin'),
    ]

    id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=50, unique=True)
    username = models.CharField(max_length=50)
    user_type = models.CharField(
        max_length=10, choices=USER_TYPES, default=STUDENT)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    objects = CustomUserManager()

    def __str__(self):
        return self.username

    def delete(self, using=None, keep_parents=False):
        first_superuser_id = CustomUser.objects.filter(
            is_superuser=True).order_by('id').first().id
        if self.is_superuser and self.id == first_superuser_id:
            raise PermissionDenied("The first superuser cannot be deleted.")
        super().delete(using=using, keep_parents=keep_parents)


class AdminProfile(models.Model):
    MALE = 'male'
    FEMALE = 'female'
    OTHER = 'other'
    SEX_TYPES = [
        (MALE, 'Male'),
        (FEMALE, 'Female'),
        (OTHER, 'Other')
    ]
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    school = models.ForeignKey(
        School, on_delete=models.CASCADE, null=True, blank=True, related_name='admin_profiles')

    sex = models.CharField(max_length=10, choices=SEX_TYPES, default=OTHER)
    phone_number = models.CharField(max_length=30, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_pic = models.ImageField(
        upload_to='profile_pics/', null=True, blank=True)
    address = models.TextField(blank=True)

    objects = models.Manager()

    def __str__(self):
        return f"{self.user.username}'s admin profile"


class TeacherProfile(models.Model):
    MALE = 'male'
    FEMALE = 'female'
    OTHER = 'other'
    SEX_TYPES = [
        (MALE, 'Male'),
        (FEMALE, 'Female'),
        (OTHER, 'Other')
    ]
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    school = models.ForeignKey(
        School, on_delete=models.CASCADE, related_name='teacher_profiles', null=True, blank=True)

    sex = models.CharField(max_length=10, choices=SEX_TYPES, default=OTHER)
    phone_number = models.CharField(max_length=30, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_pic = models.ImageField(
        upload_to='profile_pics/', null=True, blank=True)
    address = models.TextField(blank=True)

    subject = models.ManyToManyField(Subject, blank=True)

    objects = models.Manager()

    def __str__(self):
        return f"{self.user.username}'s teacher profile"


class StudentProfile(models.Model):
    MALE = 'male'
    FEMALE = 'female'
    OTHER = 'other'
    UNDERGRADUATE = 'undergraduate'
    GRADUATE = 'graduate'

    SEX_TYPES = [
        (MALE, 'Male'),
        (FEMALE, 'Female'),
        (OTHER, 'Other')
    ]

    GRADUATE_TYPE = [
        (UNDERGRADUATE, 'Undergraduate'),
        (GRADUATE, 'Graduate')
    ]

    student_id = models.CharField(
        max_length=30, blank=True, default="", unique=True)
    user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, primary_key=True)

    sex = models.CharField(max_length=10, choices=SEX_TYPES, default=OTHER)
    phone_number = models.CharField(max_length=30, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_pic = models.ImageField(
        upload_to='profile_pics/', null=True, blank=True)
    address = models.TextField(blank=True)

    guardian_name = models.CharField(max_length=255, blank=True)
    guardian_phone = models.CharField(max_length=30, blank=True)
    guardian_phone2 = models.CharField(max_length=30, blank=True)

    subject = models.ManyToManyField(Subject, blank=True)
    cohort = models.ForeignKey(
        Cohort, on_delete=models.DO_NOTHING, null=True, blank=True, related_name='students')
    status = models.CharField(choices=GRADUATE_TYPE,
                              default=UNDERGRADUATE, max_length=20)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    objects = models.Manager()

    def __str__(self):
        return f"{self.user.username}'s student profile"

    def generate_student_id(self):
        last_student = StudentProfile.objects.filter().order_by('-student_id').first()

        if last_student:
            last_id = int(last_student.student_id.split('-')[-1])
        else:
            last_id = 0

        school_name = "lightecfa".upper()
        new_id = f'{school_name}-{last_id + 1:03d}'
        return new_id

    def save(self, *args, **kwargs):
        if not self.student_id:
            self.student_id = self.generate_student_id()
        super().save(*args, **kwargs)

# =====================================================  Other models


class ScheduledInvoiceMail(models.Model):
    """ This model is for scheduling the invoice mails """
    id = models.AutoField(primary_key=True)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    scheduled_date = models.DateField()
    paidStudents = models.ManyToManyField(
        CustomUser, blank=True)
    course = models.ForeignKey(Course, on_delete=models.DO_NOTHING)
    sent = models.BooleanField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    attachment = models.FileField(
        upload_to='attachments/', blank=True, null=True)
    objects = models.Manager()


class Attendance(models.Model):
    id = models.AutoField(primary_key=True)
    subject_id = models.ForeignKey(Subject, on_delete=models.DO_NOTHING)
    attendance_date = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class AttendanceReport(models.Model):
    id = models.AutoField(primary_key=True)
    student_id = models.ForeignKey(StudentProfile, on_delete=models.DO_NOTHING)
    attendance_id = models.ForeignKey(Attendance, on_delete=models.CASCADE)
    status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class LeaveReportStudent(models.Model):
    id = models.AutoField(primary_key=True)
    student_id = models.ForeignKey(StudentProfile, on_delete=models.CASCADE)
    leave_date = models.CharField(max_length=255)
    leave_message = models.TextField()
    leave_status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class LeaveReportTeacher(models.Model):
    id = models.AutoField(primary_key=True)
    teacher_id = models.ForeignKey(TeacherProfile, on_delete=models.CASCADE)
    leave_date = models.CharField(max_length=255)
    leave_message = models.TextField()
    leave_status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class FeedBackStudent(models.Model):
    id = models.AutoField(primary_key=True)
    student_id = models.ForeignKey(StudentProfile, on_delete=models.CASCADE)
    feedback = models.TextField()
    feedback_reply = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class FeedBackTeacher(models.Model):
    id = models.AutoField(primary_key=True)
    teacher_id = models.ForeignKey(TeacherProfile, on_delete=models.CASCADE)
    feedback = models.TextField()
    feedback_reply = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class NotificationStudent(models.Model):
    id = models.AutoField(primary_key=True)
    student_id = models.ForeignKey(StudentProfile, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class NotificationTeacher(models.Model):
    id = models.AutoField(primary_key=True)
    teacher_id = models.ForeignKey(TeacherProfile, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


class TestModel(models.Model):
    id = models.AutoField(primary_key=True)
    test_name = models.CharField(max_length=255, default='')
    subject = models.ForeignKey(Subject, on_delete=models.DO_NOTHING)
    course = models.ForeignKey(Course, on_delete=models.DO_NOTHING)
    attachment = models.FileField(
        upload_to='test_files/', blank=True, null=True)
    date = models.DateField()
    objects = models.Manager()

    def __str__(self) -> str:
        return self.test_name


class TestStudentReport(models.Model):
    id = models.AutoField(primary_key=True)
    course = models.ForeignKey(Course, on_delete=models.DO_NOTHING)
    test = models.ForeignKey(TestModel, on_delete=models.DO_NOTHING)
    json = models.JSONField(null=True)

    objects = models.Manager()

    def __str__(self) -> str:
        return self.course + "-" + self.test


def change_user_type(user, new_user_type):
    """Change the user type for a given user."""
    if new_user_type not in [CustomUser.STUDENT]:
        raise ValidationError("Invalid user type")

    user_type = user.user_type
    if user_type == CustomUser.ADMIN:
        admin_profile = AdminProfile.objects.get(user=user)
        admin_profile.delete()
        user.user_type = new_user_type
        user.save()
        StudentProfile.objects.create(user=user)

        return user


@receiver(post_migrate)
def generate_permissions(sender, **kwargs):
    all_permissions = Permission.objects.all()

    # Teacher permissions
    teacher_models = [TeacherProfile]
    teacher_permissions = set()
    for model in teacher_models:
        content_type = ContentType.objects.get_for_model(model)
        permissions = Permission.objects.filter(content_type=content_type)
        teacher_permissions.update(permissions)

    # Student permissions
    student_models = [StudentProfile]
    student_permissions = set()
    for model in student_models:
        content_type = ContentType.objects.get_for_model(model)
        permissions = Permission.objects.filter(content_type=content_type)
        student_permissions.update(permissions)

    # Assign permissions to groups
    admin_group, _ = Group.objects.get_or_create(name='Admins')
    teacher_group, _ = Group.objects.get_or_create(name='Teachers')
    student_group, _ = Group.objects.get_or_create(name='Students')

    admin_group.permissions.set(all_permissions)
    teacher_group.permissions.set(teacher_permissions)
    student_group.permissions.set(student_permissions)


@receiver(post_migrate)
def create_email(sender, **kwargs):
    objects = EmailCredentials.objects.all()
    if objects.exists():
        pass
    else:
        print("Creating auto email")
        EmailCredentials.objects.create(
            email="sai.hanhtetsan@gmail.com",
            password="rtis rwxh lonq xnst"
        )


@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        if instance.user_type == CustomUser.ADMIN:
            AdminProfile.objects.create(user=instance)
            instance.groups.add(Group.objects.get(name='Admins'))
        elif instance.user_type == CustomUser.TEACHER:
            TeacherProfile.objects.create(user=instance)
            instance.groups.add(Group.objects.get(name='Teachers'))
        elif instance.user_type == CustomUser.STUDENT:
            StudentProfile.objects.create(user=instance)
            instance.groups.add(Group.objects.get(name='Students'))


@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    if instance.user_type == CustomUser.ADMIN:
        instance.adminprofile.save()
    if instance.user_type == CustomUser.TEACHER:
        instance.teacherprofile.save()
    if instance.user_type == CustomUser.STUDENT:
        instance.studentprofile.save()


# @receiver(post_save, sender=AdminProfile)
# @receiver(post_save, sender=TeacherProfile)
# @receiver(post_save, sender=StudentProfile)
# def insert_first_school(sender, instance, created, **kwargs):
#     if created and not instance.school:
#         try:
#             last_school = School.objects.last()
#             instance.school = last_school
#             instance.save()
#         except School.DoesNotExist:
#             pass
