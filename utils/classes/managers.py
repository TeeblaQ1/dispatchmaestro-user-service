from django.db import models
from django.db.models.query import QuerySet
from utils.constants import ACTIVE, DELETED


class NonDeletedObjectsManager(models.Manager):
  def get_queryset(self) -> QuerySet:
    return super().get_queryset().exclude(status=DELETED)


class ActiveObjectsManager(models.Manager):
  def get_queryset(self) -> QuerySet:
    return super().get_queryset().filter(status=ACTIVE)
  