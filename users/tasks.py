from celery import shared_task
from utils.tasks import BaseTaskWithRetry, only_one
from users.utils import UsersUtil
from users.models import User

@shared_task(bind=True, base=BaseTaskWithRetry, name='send_client_verification_mail_job')
@only_one
def send_client_verification_mail_job(self, user_id, entity_info):
    user = User.objects.get(entity_id=user_id)
    UsersUtil.send_verification_mail(entity_info=entity_info, user=user)
