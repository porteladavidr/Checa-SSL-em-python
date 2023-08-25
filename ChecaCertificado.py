import socket
import ssl
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def is_secure(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception as e:
        return False

def get_ssl_expiry_date(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                expiry_date = x509_cert.not_valid_after
                return expiry_date
    except Exception as e:
        raise Exception(f"Erro ao verificar o certificado SSL de {host}: {e}")

def send_email(subject, message):
    sender_email = "seu email"
    sender_password = "chave para acesso de aplicação externa do seu email"
    receiver_email = "destinatario"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    body = message
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print("E-mail enviado com sucesso!")
    except Exception as e:
        print("Erro ao enviar o e-mail:", e)

if __name__ == "__main__":
    try:
        with open("check-urls.txt", "r") as file:
            websites = file.read().splitlines()

        for website in websites:
            try:
                if is_secure(website):
                    expiry_date = get_ssl_expiry_date(website)
                    current_date = datetime.now()

                    if expiry_date > current_date:
                        days_remaining = (expiry_date - current_date).days
                        if days_remaining <= 60:
                            alert_message = f"ALERTA: O certificado SSL de {website} expira em {days_remaining} dias, em {expiry_date}."
                            send_email(f"Aviso de Certificado Expirando {website} ", alert_message)
                    else:
                        print(f"O certificado SSL de {website} já expirou em {expiry_date}.")
                else:
                    print(f"O site {website} não é seguro, verificando na porta 80.")
                    try:
                        with socket.create_connection((website, 80)) as sock:
                            print(f"O site {website} na porta 80 está acessível.")
                            expiry_date = get_ssl_expiry_date(website, port=80)
                            current_date = datetime.now()

                            if expiry_date > current_date:
                                days_remaining = (expiry_date - current_date).days
                                if days_remaining <= 60:
                                    alert_message = f"ALERTA: O certificado SSL de {website} (na porta 80) expira em {days_remaining} dias, em {expiry_date}."
                                    send_email(f"Aviso de Certificado Expirando {website} (porta 80) ", alert_message)
                            else:
                                print(f"O certificado SSL de {website} (na porta 80) já expirou em {expiry_date}.")
                    except Exception as e:
                        print(f"O site {website} não é acessível na porta 80: {e}")
            except Exception as e:
                print(e)
    except Exception as e:
        print("Erro ao ler o arquivo de sites:", e)
