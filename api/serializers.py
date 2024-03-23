
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate

from api.models import *

User = get_user_model()


class UserUpdateSeriaizer(serializers.ModelSerializer):
    def get(self, request):
        return None


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'user_type']

    def create(self, clean_data):
        user_obj = User.objects.create_user(
            email=clean_data['email'],
            password=clean_data['password'],
            username=clean_data['username'],
            user_type=clean_data['user_type'],
        )
        return user_obj


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def check_user(self, clean_data):
        email = clean_data['email']
        password = clean_data['password']
        user = authenticate(username=email, password=password)
        if not user:
            raise ValueError("User does not exist!")
        return user


class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminProfile
        fields = '__all__'


class TeacherProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeacherProfile
        fields = '__all__'


class StudentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = '__all__'


class UserDetailSerializer(serializers.ModelSerializer):
    admin_profile = AdminProfileSerializer(
        source='adminprofile', read_only=True)
    teacher_profile = TeacherProfileSerializer(
        source='teacherprofile', read_only=True)
    student_profile = StudentProfileSerializer(
        source='studentprofile', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'user_type', 'date_joined',
                  'admin_profile', 'teacher_profile', 'student_profile', 'password']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        user_type = instance.user_type
        if user_type == User.ADMIN:
            admin_profile_data = data.get('admin_profile', {})
            admin_profile_data.pop('user', None)
            data['profile'] = admin_profile_data
            data.pop('admin_profile')
            data.pop('teacher_profile')
            data.pop('student_profile')
        elif user_type == User.TEACHER:
            teacher_profile_data = data.get('teacher_profile', {})
            teacher_profile_data.pop('user', None)
            data['profile'] = teacher_profile_data
            data.pop('admin_profile')
            data.pop('teacher_profile')
            data.pop('student_profile')
        elif user_type == User.STUDENT:
            student_profile_data = data.get('student_profile', {})
            data['profile'] = student_profile_data
            data.pop('admin_profile')
            data.pop('teacher_profile')
            data.pop('student_profile')

        return data


class TeacherRegisterSerializer(serializers.ModelSerializer):
    sex = serializers.ChoiceField(
        choices=TeacherProfile.SEX_TYPES, default=TeacherProfile.OTHER)
    phone_number = serializers.CharField(max_length=30, required=False)
    date_of_birth = serializers.DateField(required=False)
    profile_pic = serializers.ImageField(required=False)
    address = serializers.CharField(max_length=255, required=False)
    subject = serializers.PrimaryKeyRelatedField(
        queryset=Subject.objects.all(), many=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'sex',
                  'phone_number', 'date_of_birth', 'profile_pic', 'address', 'subject']

    def create(self, validated_data):
        subjects = []
        try:
            for subject_id in validated_data['subject']:
                subject_obj = Subject.objects.get(id=int(subject_id))
                subjects.append(subject_obj)
        except Subject.DoesNotExist:
            raise ValidationError("One or more subjects not found")

        user_obj = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            username=validated_data['username'],
            user_type=CustomUser.TEACHER)

        try:
            teacher_profile = TeacherProfile.objects.get(user=user_obj)
        except TeacherProfile.DoesNotExist:
            teacher_profile = TeacherProfile.objects.create(user=user_obj)

        teacher_profile.sex = validated_data.get('sex', teacher_profile.sex)
        teacher_profile.phone_number = validated_data.get(
            'phone_number', teacher_profile.phone_number)
        teacher_profile.date_of_birth = validated_data.get(
            'date_of_birth', teacher_profile.date_of_birth)
        teacher_profile.address = validated_data.get(
            'address', teacher_profile.address)
        teacher_profile.subject.set(subjects)

        profile_pic = validated_data.get('profile_pic')

        if profile_pic:
            teacher_profile.profile_pic = profile_pic
        teacher_profile.save()

        return user_obj


class AdminRegisterSerializer(serializers.ModelSerializer):
    sex = serializers.ChoiceField(
        choices=AdminProfile.SEX_TYPES, default=AdminProfile.OTHER)
    phone_number = serializers.CharField(max_length=30, required=False)
    date_of_birth = serializers.DateField(required=False)
    profile_pic = serializers.ImageField(required=False)
    address = serializers.CharField(max_length=255, required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'sex',
                  'phone_number', 'date_of_birth', 'profile_pic', 'address']

    def create(self, validated_data):
        user_obj = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            username=validated_data['username'],
            user_type=CustomUser.ADMIN)

        try:
            admin_profile = AdminProfile.objects.get(user=user_obj)
        except AdminProfile.DoesNotExist:
            admin_profile = AdminProfile.objects.create(user=user_obj)

        admin_profile.sex = validated_data.get('sex', admin_profile.sex)
        admin_profile.phone_number = validated_data.get(
            'phone_number', admin_profile.phone_number)
        admin_profile.date_of_birth = validated_data.get(
            'date_of_birth', admin_profile.date_of_birth)
        admin_profile.address = validated_data.get(
            'address', admin_profile.address)
        profile_pic = validated_data.get('profile_pic')
        if profile_pic:
            admin_profile.profile_pic = profile_pic
        admin_profile.save()

        return user_obj


class StudentRegisterSerializer(serializers.ModelSerializer):
    sex = serializers.ChoiceField(
        choices=StudentProfile.SEX_TYPES, default=StudentProfile.OTHER)
    phone_number = serializers.CharField(max_length=30, required=False)
    date_of_birth = serializers.DateField(required=False)
    profile_pic = serializers.ImageField(required=False, default=None)
    address = serializers.CharField(max_length=255, required=False)
    guardian_name = serializers.CharField(max_length=255, required=False)
    guardian_phone = serializers.CharField(max_length=30, required=False)
    guardian_phone2 = serializers.CharField(max_length=30, required=False)
    cohort = serializers.PrimaryKeyRelatedField(
        queryset=Cohort.objects.all(), required=True)
    subject = serializers.PrimaryKeyRelatedField(
        queryset=Subject.objects.all(), many=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'sex',
                  'phone_number', 'date_of_birth', 'profile_pic', 'address', 'guardian_name', 'guardian_phone', 'guardian_phone2', 'cohort', 'subject']

    def create(self, validated_data):
        cohort = validated_data.pop('cohort', None)[0]
        subject_ids = validated_data.pop('subject', [])

        try:
            cohort = Cohort.objects.get(id=int(cohort))
        except Exception as e:
            raise ValidationError('need to add cohort')

        subjects = []
        for subject_id in subject_ids:
            try:
                subject = Subject.objects.get(id=subject_id)
                subjects.append(subject)
            except Subject.DoesNotExist:
                raise ValidationError(
                    f"Subject with ID {subject_id} not found.")

        user_obj = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            username=validated_data['username'],
            user_type=CustomUser.STUDENT)

        try:
            student_profile = StudentProfile.objects.get(user=user_obj)
        except StudentProfile.DoesNotExist:
            student_profile = StudentProfile.objects.create(user=user_obj)

        if cohort and subject:
            try:
                student_profile = StudentProfile.objects.get(pk=user_obj.id)
                student_profile.sex = validated_data.get(
                    'sex', student_profile.sex)
                student_profile.phone_number = validated_data.get(
                    'phone_number', student_profile.phone_number)
                student_profile.date_of_birth = validated_data.get(
                    'date_of_birth', student_profile.date_of_birth)
                student_profile.address = validated_data.get(
                    'address', student_profile.address)
                student_profile.guardian_name = validated_data.get(
                    'guardian_name', student_profile.guardian_name)
                student_profile.guardian_phone = validated_data.get(
                    'guardian_phone', student_profile.guardian_phone)
                student_profile.guardian_phone2 = validated_data.get(
                    'guardian_phone2', student_profile.guardian_phone2)
                student_profile.cohort = cohort
                student_profile.subject.set(subjects)
                profile_pic = validated_data.get('profile_pic')
                if profile_pic:
                    student_profile.profile_pic = profile_pic
                student_profile.save()

            except Exception as e:
                user_obj.delete()
                print(e)
                raise serializers.ValidationError(
                    "Error creating student profile.")

        user_data = UserDetailSerializer(user_obj).data
        return user_obj


class UserTypeChangeSerializer(serializers.ModelSerializer):
    _id = serializers.IntegerField(write_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('_id', 'password', 'user_type')

    def validate(self, attrs):
        user_id = attrs.get('_id')
        password = attrs.get('password')
        instance = self.instance
        try:
            instance = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        if not check_password(password, instance.password):
            raise serializers.ValidationError("Incorrect password.")

        return attrs

    def save(self, **kwargs):
        user_type = self.validated_data.get('user_type')
        if user_type is None:
            raise serializers.ValidationError("User type is required.")

        user_id = self.validated_data.get('_id')
        instance = CustomUser.objects.get(id=user_id)

        instance.user_type = user_type
        instance.save()
        return instance


class CourseDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = '__all__'

    def create(self, validated_data):
        course = Course.objects.create(**validated_data)
        return course


class SubjectDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = '__all__'


class CohortDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cohort
        fields = ('id', 'cohort_name',
                  'session_start_date', 'session_end_date', 'course')

    def create(self, validated_data):
        return super().create(validated_data)


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ('__all__')


class ScheduledInvoiceMailSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledInvoiceMail
        fields = ('__all__')


class EmailCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailCredentials
        fields = ('__all__')


class ScheduledEmailSerializer(serializers.ModelSerializer):
    attachment = serializers.FileField(required=False)

    class Meta:
        model = ScheduledInvoiceMail
        fields = ('email', 'subject', 'message',
                  'scheduled_date', 'attachment')

    def validate_attachment(self, value):
        max_size = 10 * 1024 * 1024  # 10 MB
        if value.size > max_size:
            raise serializers.ValidationError(
                "File size is too large (max size is 10 MB)")
        return value


class AttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class AttendanceReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttendanceReport
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class LeaveReportStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveReportStudent
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class LeaveReportTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveReportTeacher
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class FeedBackStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedBackStudent
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class FeedBackTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedBackTeacher
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class NotificationStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationStudent
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class NotificationTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationTeacher
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)
