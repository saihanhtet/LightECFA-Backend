from django.contrib.auth.models import Group
from django import forms
from django.contrib import admin
from .models import *

admin.site.register(School)
admin.site.register(AdminProfile)
admin.site.register(TeacherProfile)
admin.site.register(Course)
admin.site.register(Cohort)
admin.site.register(Subject)
admin.site.register(Attendance)
admin.site.register(AttendanceReport)
admin.site.register(LeaveReportStudent)
admin.site.register(LeaveReportTeacher)
admin.site.register(NotificationStudent)
admin.site.register(NotificationTeacher)
admin.site.register(FeedBackStudent)
admin.site.register(FeedBackTeacher)
admin.site.register(Invoice)
admin.site.register(EmailCredentials)
admin.site.register(ScheduledInvoiceMail)


class UserForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('__all__')


class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'user_type', 'is_staff', 'is_superuser')
    search_fields = ('email', 'username',)
    list_filter = ('user_type', 'is_staff', 'is_superuser')
    form = UserForm

    def save_model(self, request, obj, form, change):
        new_user_type = form.cleaned_data['user_type']
        try:
            previous = CustomUser.objects.get(id=obj.id)
            previous_user_type = previous.user_type
            if previous_user_type == CustomUser.ADMIN:
                AdminProfile.objects.get(user=obj).delete()
            elif previous_user_type == CustomUser.TEACHER:
                TeacherProfile.objects.get(user=obj).delete()
            elif previous_user_type == CustomUser.STUDENT:
                StudentProfile.objects.get(user=obj).delete()
        except (AdminProfile.DoesNotExist, TeacherProfile.DoesNotExist, StudentProfile.DoesNotExist, CustomUser.DoesNotExist):
            print('error no profile found')

        if change:
            if new_user_type == CustomUser.ADMIN:
                print('changing to admin')
                AdminProfile.objects.create(user=obj)
                obj.is_superuser = True
                obj.is_staff = True
                admin_group = Group.objects.get(name='Admins')
                obj.groups.clear()
                obj.groups.add(admin_group)

            elif new_user_type == CustomUser.TEACHER:
                print('changing to teacher')
                TeacherProfile.objects.create(user=obj)
                obj.is_superuser = False
                obj.is_staff = True
                teacher_group = Group.objects.get(name='Teachers')
                obj.groups.clear()
                obj.groups.add(teacher_group)

            elif new_user_type == CustomUser.STUDENT:
                print('changing to student')
                StudentProfile.objects.create(user=obj)
                obj.is_superuser = False
                obj.is_staff = False
                student_group = Group.objects.get(name='Students')
                obj.groups.clear()
                obj.groups.add(student_group)

        obj.user_type = new_user_type
        obj.save()

        if obj.user_type == CustomUser.ADMIN:
            obj.is_superuser = True
            obj.is_staff = True
            admin_group = Group.objects.get(name='Admins')
            obj.groups.add(admin_group)

        elif obj.user_type == CustomUser.TEACHER:
            obj.is_superuser = False
            obj.is_staff = True
            teacher_group = Group.objects.get(name='Teachers')
            obj.groups.add(teacher_group)

        elif obj.user_type == CustomUser.STUDENT:
            obj.is_superuser = False
            obj.is_staff = False
            student_group = Group.objects.get(name='Students')
            obj.groups.add(student_group)

        obj.save()
        print(change, obj.groups)

        super().save_model(request, obj, form, change)


class StudentProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'cohort', 'status')
    search_fields = ('user__email', 'user__username')
    list_filter = ('cohort',)


admin.site.register(StudentProfile, StudentProfileAdmin)
admin.site.register(CustomUser, CustomUserAdmin)
