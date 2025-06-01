from django.core.management.base import BaseCommand
from django.db import transaction
from users.models import User, ClientInfo, PartnerInfo
from services.core import DispatchMaestro
from utils.constants import CLIENT, PARTNER
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Syncs client and partner information from core service to local database'

    def handle(self, *args, **options):
        core_service = DispatchMaestro()
        synced_clients = 0
        synced_partners = 0
        failed_syncs = 0

        self.stdout.write('Starting entity info sync...')

        # Sync all users
        users = User.objects.all()
        total_users = users.count()

        for user in users:
            try:
                with transaction.atomic():
                    if user.entity_type == CLIENT:
                        # Get client info from core service
                        client_info = core_service.get_client_info(entity_id=str(user.entity_id))
                        if client_info and client_info.get('data'):
                            data = client_info['data']
                            # Update or create client info
                            ClientInfo.objects.update_or_create(
                                id=user.entity_id,
                                user=user,
                                defaults={
                                    'first_name': data.get('first_name'),
                                    'last_name': data.get('last_name'),
                                    'email_address': data.get('email_address'),
                                    'phone_number': data.get('phone_number'),
                                    'description': data.get('description'),
                                    'website_url': data.get('website_url'),
                                    'role': data.get('role'),
                                    'status': data.get('status'),
                                    'country': data.get('country'),
                                    'business_name': data.get('business_name'),
                                    'logo': data.get('logo'),
                                    'meta': data.get('meta', {})
                                }
                            )
                            synced_clients += 1
                            self.stdout.write(f'Synced client info for {user.email}')

                    elif user.entity_type == PARTNER:
                        # Get partner info from core service
                        partner_info = core_service.get_partner_info(entity_id=str(user.entity_id))
                        if partner_info and partner_info.get('data'):
                            data = partner_info['data']
                            partner_data = data.get('partner', {})
                            # Update or create partner info
                            PartnerInfo.objects.update_or_create(
                                id=user.entity_id,
                                user=user,
                                defaults={
                                    'name': partner_data.get('business_name'),
                                    'email_address': partner_data.get('email_address'),
                                    'phone_number': data.get('phone_number'),
                                    'description': partner_data.get('description'),
                                    'website_url': data.get('website_url'),
                                    'status': partner_data.get('status', 'ACTIVE'),
                                    'country': partner_data.get('country'),
                                    'logo': partner_data.get('logo'),
                                    'meta': {
                                        **partner_data.get('meta', {}),
                                        **data.get('meta', {})
                                    }
                                }
                            )
                            synced_partners += 1
                            self.stdout.write(f'Synced partner info for {user.email}')

            except Exception as e:
                failed_syncs += 1
                logger.error(f'Failed to sync entity info for {user.email}: {str(e)}')
                self.stdout.write(self.style.ERROR(f'Failed to sync entity info for {user.email}: {str(e)}'))
                continue

        # Print summary
        self.stdout.write('\nSync Summary:')
        self.stdout.write(f'Total users processed: {total_users}')
        self.stdout.write(f'Successfully synced clients: {synced_clients}')
        self.stdout.write(f'Successfully synced partners: {synced_partners}')
        self.stdout.write(f'Failed syncs: {failed_syncs}')

        if failed_syncs == 0:
            self.stdout.write(self.style.SUCCESS('\nSync completed successfully!'))
        else:
            self.stdout.write(self.style.WARNING('\nSync completed with some failures. Check logs for details.')) 