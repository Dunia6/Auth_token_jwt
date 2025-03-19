from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile

@receiver(post_save, sender=User)
def create_or_update_profile(sender, instance, created, **kwargs):
    """
    Crée un profil lors de la création d'un nouvel utilisateur.
    Met à jour le profil si l'utilisateur est modifié.
    """
    if created:
        Profile.objects.create(
            user=instance,
            first_name=instance.first_name,
            last_name=instance.last_name,
            email=instance.email
        )
    else:
        instance.profile.save()


@receiver(post_save, sender=Profile)
def update_user_from_profile(sender, instance, **kwargs):
    user = instance.user

    changes = False

    if instance.first_name and user.first_name != instance.first_name:
        user.first_name = instance.first_name
        changes = True

    if instance.last_name and user.last_name != instance.last_name:
        user.last_name = instance.last_name
        changes = True

    if instance.email and user.email != instance.email:
        user.email = instance.email
        changes = True

    if changes:
        user.save()