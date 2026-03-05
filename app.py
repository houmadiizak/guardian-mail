# --- CONFIGURATION ET STYLE ---
st.set_page_config(page_title="Guardian Mail AI", page_icon="🛡️", layout="wide")

# Remplace par ta vraie clé API VirusTotal
VT_API_KEY = "VOTRE_CLE_API_ICI"

# --- FONCTIONS TECHNIQUES ---
def extraire_liens(texte):
    return list(set(re.findall(r'(https?://[^\s]+)', texte)))

def verifier_fichier_vt(file_content):
file_hash = hashlib.sha256(file_content).hexdigest()
url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
headers = {"x-apikey": VT_API_KEY}
try:
response = requests.get(url, headers=headers)
if response.status_code == 200:
stats = response.json()['data']['attributes']['last_analysis_stats']
return stats['malicious'], file_hash
return 0, file_hash
except:
return None, file_hash

# --- NAVIGATION LATÉRALE ---
st.sidebar.title("🛡️ Guardian Mail")
st.sidebar.markdown("Système de protection contre le phishing")
menu = st.sidebar.radio("Outils disponibles :", ["Analyse de Message", "Scan de Pièce Jointe", "Vérification d'Expéditeur"])

# --- PAGE 1 : ANALYSE DE MESSAGE ---
if menu == "Analyse de Message":
st.header("🔍 Analyse de contenu et de liens")
message = st.text_area("Collez le corps du mail ici :", height=250)

if st.button("Lancer l'audit du texte"):
if message:
liens = extraire_liens(message)
col1, col2 = st.columns(2)

with col1:
st.subheader("Analyse psychologique")
mots_urgents = ["urgent", "immédiatement", "suspendu", "bloqué", "pénalité"]
trouves = [m for m in mots_urgents if m in message.lower()]
if trouves:
st.warning(f"⚠️ Ton alarmiste détecté ({', '.join(trouves)})")
else:
st.success("✅ Ton du message semble neutre.")

with col2:
st.subheader("Analyse des liens")
if liens:
st.info(f"🔗 {len(liens)} lien(s) détecté(s).")
for l in liens:
st.code(l)
else:
st.success("✅ Aucun lien détecté.")
else:
st.error("Veuillez saisir un texte.")

# --- PAGE 2 : SCAN DE PIÈCE JOINTE ---
elif menu == "Scan de Pièce Jointe":
st.header("📁 Analyseur de fichiers malveillants")
fichier = st.file_uploader("Téléchargez la pièce jointe suspecte", type=None)

if fichier:
if st.button("Vérifier l'empreinte numérique"):
detections, h = verifier_fichier_vt(fichier.read())
st.info(f"ADN du fichier (SHA-256) : `{h}`")
if detections is None:
st.error("Erreur de connexion aux bases de données.")
elif detections > 0:
st.error(f"🚨 DANGER : Ce fichier est marqué comme MALVEILLANT par {detections} antivirus !")
else:
st.success("✅ Ce fichier est propre selon les bases de données mondiales.")

# --- PAGE 3 : VÉRIFICATION EXPÉDITEUR ---
elif menu == "Vérification d'Expéditeur":
st.header("📧 Audit de l'adresse mail")
email = st.text_input("Adresse de l'expéditeur (ex: service@paypal-com.fr)")

if st.button("Vérifier la cohérence"):
if "@" in email:
domaine = email.split("@")[-1]
if len(domaine.split('.')) > 2:
st.warning(f"⚠️ Le domaine '{domaine}' semble complexe. Soyez vigilant.")
else:
st.info(f"Analyse du domaine `{domaine}` terminée.")
else:
st.error("Adresse mail invalide.")

st.sidebar.markdown("---")
st.sidebar.caption("Propulsé par Streamlit & VirusTotal")

