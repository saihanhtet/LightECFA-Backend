from django.urls import path
from . import views

urlpatterns = [
    # check token
    path('check-token', views.CheckToken.as_view(), name='check-token'),

    # auth urls
    path('login', views.LoginView.as_view(), name='login'),
    path('register', views.RegisterView.as_view(), name='register'),
    path('logout', views.LogoutView.as_view(), name='logout'),

    # user urls
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('user_type/<str:user_type>', views.UserListView.as_view(),
         name='user-list-filtered'),
    path('users/<int:pk>', views.UserDetailView.as_view(), name='user-detail'),
    # path('user/change', views.UserTypeChangeView.as_view(),
    #     name="user-type-change"),

    #  course urls
    path('courses', views.CourseView.as_view(), name="course-list"),
    path('courses/<int:pk>', views.CourseDetailView.as_view(), name='course-detail'),

    # subject urls
    path('subjects', views.SubjectView.as_view(), name="subject-list"),
    path('subjects/<int:pk>', views.SubjectDetailView.as_view(),
         name='subject-detail'),

    # subject urls
    path('cohorts', views.CohortView.as_view(), name="cohort-list"),
    path('cohorts/<int:pk>', views.CohortDetailView.as_view(),
         name='cohort-detail'),

    # student urls
    path('student/create', views.StudentRegisterView.as_view(),
         name="student-create"),
    path('student/<int:pk>', views.StudentProfileDetailView.as_view(),
         name="student-update"),
    # teacher urls
    path('teacher/create', views.TeacherRegisterView.as_view(),
         name="teacher-create"),
    path('teacher/<int:pk>', views.TeacherProfileDetailView.as_view(),
         name="teacher-update"),

    # admin urls
    path('admin/create', views.AdminRegisterView.as_view(),
         name="admin-create"),
    path('admin/<int:pk>', views.AdminProfileDetailView.as_view(),
         name="admin-update"),

    path('dashboard', views.Dashboard.as_view(), name='dashboard'),

    path('invoice', views.InvoiceFileUpload.as_view(), name='invoice'),
    path('invoice/<int:pk>', views.InvoiceFileUploadDetail.as_view(),
         name='invoice-details'),

    path('send-invoice/all', views.SendAllInvoice.as_view(),
         name='send-all-invoice'),
    path('schedule/invoice', views.ScheduledInvoiceMailView.as_view(),
         name="schedule-invoice"),
    path('schedule/invoice/<int:pk>', views.ScheduledInvoiceMailDetail.as_view(),
         name="schedule-invoice-detail"),


    path('send-email/all', views.SendEmailView.as_view(), name="send-email-all"),
    path('email-credentials',
         views.EmailCredentialsDetailView.as_view(), name="email-credentials"),
    path('send-email/<int:pk>',
         views.ScheduledInvoiceMailSend.as_view(), name="send-email"),

    # excels
    path('excel/admin',
         views.AdminUserExcelView.as_view(), name="excel-admin"),
    path('excel/teacher',
         views.TeacherUserExcelView.as_view(), name="excel-teacher"),
    path('excel/student',
         views.StudentUserExcelView.as_view(), name="excel-student"),

    # test
    path('test/',
         views.TestMakerView.as_view(), name="test-view"),
    path('test/report',
         views.TestMakerDetailView.as_view(), name="test-report"),
    path('test/<int:pk>',
         views.TestMakerDetailView.as_view(), name="test-detail"),
    path('test/report/<int:pk>',
         views.TestReportDetailView.as_view(), name="test-report-detail"),
]
