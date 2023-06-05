from django_cron import CronJobBase, Schedule
from auth_app import models

MIN_ATTEMPTS = 0


class DeleteAttemptsJob(CronJobBase):
    RUN_AT_TIMES = ['00:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'auth_app.delete_all_attemps_job'

    def do(self):
        # Lógica para borrar los atributos del modelo AdmonGlobal
        models.AdmonGlobal.objects.all().update(
            intentos=MIN_ATTEMPTS, timestamp_ultimo_intento=None, ipv4_address=None)
