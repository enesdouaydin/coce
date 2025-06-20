import os
import csv
import json
from pathlib import Path
from dotenv import load_dotenv
from openai import AsyncOpenAI
import pandas as pd
from fuzzywuzzy import process, fuzz # type: ignore
import random
from datetime import datetime
import asyncio
import re

# .env dosyasından ortam değişkenlerini yükle
load_dotenv()

# Global Debug Modu
DEBUG_MODE = False

# OpenRouter Asenkron İstemcisi ve Başlıklar
async_client = None
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_REFERRER_FALLBACK = "http://localhost:3000"
OPENROUTER_X_TITLE_FALLBACK = "Sifir Arac Asistani"

OPENROUTER_REFERRER = os.getenv("OPENROUTER_REFERRER", OPENROUTER_REFERRER_FALLBACK)
_raw_x_title = os.getenv("OPENROUTER_X_TITLE", OPENROUTER_X_TITLE_FALLBACK)

COMPANY_NAME = "Sıfır Araç Nokta Com"

def sanitize_header_value(value: str, fallback: str = "Default App Title") -> str:
    try:
        value.encode('ascii')
        return value
    except UnicodeEncodeError:
        replacements = {
            'ı': 'i', 'İ': 'I', 'ğ': 'g', 'Ğ': 'G',
            'ü': 'u', 'Ü': 'U', 'ş': 's', 'Ş': 'S',
            'ö': 'o', 'Ö': 'O', 'ç': 'c', 'Ç': 'C'
        }
        sanitized_value = value
        for tr_char, en_char in replacements.items():
            sanitized_value = sanitized_value.replace(tr_char, en_char)
        final_value = sanitized_value.encode('ascii', 'ignore').decode('ascii')
        if not final_value.strip():
            if DEBUG_MODE: print(f"⚠️ Header değeri '{value}' tamamen silindi, fallback '{fallback}' kullanılıyor.")
            return fallback
        if DEBUG_MODE and final_value != value:
                print(f"ℹ️ Header değeri sanitize edildi: '{value}' -> '{final_value}'")
        return final_value

SANITIZED_OPENROUTER_X_TITLE = sanitize_header_value(_raw_x_title, fallback="Generic App Title Header")

if OPENROUTER_API_KEY:
    async_client = AsyncOpenAI(
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        api_key=OPENROUTER_API_KEY,
    )
else:
    print("HATA: OPENROUTER_API_KEY .env dosyasında bulunamadı veya yüklenemedi.")

data_vehicles = [
    ['renault clio', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['clio', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['toyota yaris', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['volkswagen polo', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['hyundai i20', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['hyundai i10', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['seat ibiza', 'opel corsa', 'opel corsa elektrikli', 'peugeot 208', 'citroen c3', 'peugeot 308'],
    ['nissan x-trail', 'peugeot 5008', 'opel grandland', 'citroen c5 aircross', 'nissan xtrail', 'renault rafale'],
    ['toyota rav4', 'peugeot 5008', 'opel grandland', 'citroen c5 aircross', 'nissan xtrail', 'renault rafale'],
    ['toyota corolla cross', 'peugeot 5008', 'opel grandland', 'citroen c5 aircross', 'nissan xtrail', 'renault rafale'],
    ['hyundai bayon', 'opel crossland', 'citroen c4', 'citroen c4x', 'nissan juke', 'mokka'],
    ['fiat egea cross', 'opel crossland', 'citroen c4', 'citroen c4x', 'nissan juke', 'mokka'],
    ['skoda kamiq', 'opel crossland', 'citroen c4', 'citroen c4x', 'nissan juke', 'mokka'],
    ['seat ateca', 'opel crossland', 'citroen c4', 'citroen c4x', 'nissan qashqai', 'mokka'],
    ['ford focus hb', 'opel astra hb', 'opel astra elektrikli', 'peugeot 308', 'peugeot 308 elektrikli', None],
    ['toyota corolla hb', 'opel astra hb', 'opel astra elektrikli', 'peugeot 308', 'peugeot 308 elektrikli', None],
    ['toyota corollaa', 'opel astra hb', 'opel astra elektrikli', 'peugeot 308', 'peugeot 308 elektrikli', None],
    ['renault megane sedan', 'opel astra hb', 'opel astra elektrikli', 'peugeot 308', 'peugeot 308 elektrikli', None],
    ['hyundai elentra', 'opel astra hb', 'opel astra elektrikli', 'peugeot 308', 'peugeot 308 elektrikli', None],
    ['skoda octavia', 'opel astra hb', 'opel astra elektrikli', 'peugeot 308', 'peugeot 308 elektrikli', None],
    ['skoda kodiaq', 'opel grandland', 'peugeot 3008', 'peugeot elektrikli 2008', 'nissan xtrail', None],
    ['kia sportage', 'opel grandland', 'peugeot 3008', 'peugeot elektrikli 2008', 'nissan qashqai', None],
    ['hyundai tucson', 'opel grandland', 'peugeot 3008', 'peugeot elektrikli 2008', 'nissan xtrail', None],
    ['volkswagen tiguan', 'opel grandland', 'peugeot 3008', 'peugeot elektrikli 2008', 'nissan xtrail', None],
    ['volkswagen t-roc', 'opel mokka', 'mokka elektrikli', 'peugeot 408', 'citroen c4x', 'nissan juke'],
    ['volkswagen t-cross', 'opel mokka', 'mokka elektrikli', 'peugeot 408', 'citroen c4x', 'nissan juke'],
    ['hyundai kona', 'opel mokka', 'mokka elektrikli', 'peugeot 408', 'citroen c4x', 'nissan qashqai'],
    ['ford kuga', 'opel grandland', 'peugeot 3008', 'peugeot elektrikli 2008', 'nissan qashqai', None],
    ['ford puma', 'opel mokka', 'mokka elektrikli', 'peugeot 408', 'citroen c4x', 'nissan juke'],
    ['skoda karoq', 'opel mokka', 'mokka elektrikli', 'peugeot 408', 'citroen c4x', 'nissan qashqai'],
    ['fiat doblo combi', 'opel combo life', 'none', None, None, None],
    ['fiat fiorino combi', 'opel combo life', 'none', None, None, None],
    ['ford tourneo connect', 'citroen berlingo', 'peugeot rifter', 'peugeot partner', 'opel combo cargo', 'opel combo life'],
    ['renault megane e tech', 'peugeot elektrikli 308', 'peugeot elektrikli 2008', 'opel mokka elektrikli', 'citroen elektrikli c4', 'citroen elektrikli c4x'],
    ['jeep avenger', 'peugeot elektrikli 308', 'peugeot elektrikli 2008', 'opel mokka elektrikli', 'citroen elektrikli c4', 'citroen elektrikli c4x'],
    ['toyota chr', 'peugeot elektrikli 308', 'peugeot elektrikli 2008', 'opel mokka elektrikli', 'citroen elektrikli c4', 'citroen elektrikli c4x']
]
columns_vehicles = ['çeviri modelleri', 'eş değeri', 'elektrikli', 'öneri3', 'öneri4', 'öneri5']
df_vehicles = pd.DataFrame(data_vehicles, columns=columns_vehicles)

for col in columns_vehicles:
    df_vehicles[col] = df_vehicles[col].astype(str).str.lower().str.strip()
    df_vehicles[col].replace('none', None, inplace=True)
df_vehicles.replace('opel  corsa elektrikli', 'opel corsa elektrikli', inplace=True)
df_vehicles.replace('toyota corollaa', 'toyota corolla', inplace=True)

kullanicilar = [
    {"id": "0", "isim": "Ömer", "soyisim": "Can", "unvan": "Bey", "telefon": "5466630941", "marka": "Renault", "model": "Clio", "sehir": "İstanbul", "ilce": "Kadıköy"},
    {"id": "1", "isim": "Ayşe", "soyisim": "Yılmaz", "unvan": "Hanım", "telefon": "5301122233", "marka": "BMW", "model": "320i", "sehir": "İstanbul", "ilce": "Beşiktaş"},
    {"id": "2", "isim": "Mala", "soyisim": "Yarar", "unvan": "Hanım", "telefon": "5395029860", "marka": "Toyota", "model": "Rav4", "sehir": "İstanbul", "ilce": "Uskudar"},
    {"id": "3", "isim": "Asker", "soyisim": "Yılmaz", "unvan": "Bey", "telefon": "5302342234", "marka": "Peugeot", "model": "5008", "sehir": "Ankara", "ilce": "Eryaman"}
]

session_rejected_models = []
fuzzy_matching_model_library_list = []
MODEL_LIBRARY_CSV_PATH = r"C:\Users\dou\Desktop\21.04.o\09\yeni\datala.csv"

FEMALE_NAMES_LIST = [ "ayşe", "fatma", "zeynep", "selin", "elif", "merve", "derya", "ebru", "gamze", "aslı", "burcu", "deniz", "ece", "ipek", "özge", "gizem", "tuğçe", "damla", "pınar", "gül", "canan", "filiz", "şeyma", "hande", "latife", "belgin", "ceren", "didem", "esra", "feride", "gönül", "hale", "jale", "kezban", "leyla", "mine", "nilgün", "oya", "pelin", "rüya", "sema", "tülay", "ümmühan", "vildan", "yasemin", "zerrin", "çiğdem", "meltem", "serpil", "ışıl", "ilayda", "irem", "beste", "buse", "berra", "begüm", "mala"
]

def get_unvan(isim_str):
    if not isim_str or not isinstance(isim_str, str): return "Bey/Hanım"
    return "Hanım" if isim_str.lower() in FEMALE_NAMES_LIST else "Bey"

def load_external_model_library_from_csv(csv_file_path=MODEL_LIBRARY_CSV_PATH):
    global fuzzy_matching_model_library_list
    try:
        try: df_library = pd.read_csv(csv_file_path, encoding='utf-8')
        except UnicodeDecodeError: df_library = pd.read_csv(csv_file_path, encoding='iso-8859-9')
        all_models_set = set()
        for col in df_library.columns:
            valid_strings = df_library[col].dropna().astype(str).str.lower().str.strip()
            unique_models_in_col = valid_strings[valid_strings != ''].unique()
            all_models_set.update(unique_models_in_col)
        if 'none' in all_models_set: all_models_set.remove('none')
        if 'araç' in all_models_set: all_models_set.remove('araç')
        fuzzy_matching_model_library_list = list(all_models_set)
        if not fuzzy_matching_model_library_list:
            print(f"UYARI: '{csv_file_path}' dosyasından harici model kütüphanesi okunamadı veya boş.")
            return False
        if DEBUG_MODE: print(f"Harici model kütüphanesi {len(fuzzy_matching_model_library_list)} modelle CSV'den yüklendi.")
        return True
    except FileNotFoundError:
        print(f"HATA: CSV dosyası ('{csv_file_path}') bulunamadı."); fuzzy_matching_model_library_list = []; return False
    except pd.errors.EmptyDataError:
        print(f"HATA: CSV dosyası ('{csv_file_path}') boş."); fuzzy_matching_model_library_list = []; return False
    except Exception as e:
        print(f"HATA: CSV dosyası ('{csv_file_path}') okunurken hata: {e}"); fuzzy_matching_model_library_list = []; return False

def find_models_in_text_from_library(user_text, model_library):
    if not user_text or not model_library: return []
    user_text_lower = user_text.lower()
    found_models = set()
    sorted_library = sorted(model_library, key=len, reverse=True)
    for lib_model in sorted_library:
        pattern = r"\b" + re.escape(lib_model) + r"\b"
        if re.search(pattern, user_text_lower):
            is_substring = any(lib_model in fm for fm in found_models if len(fm) > len(lib_model))
            if not is_substring:
                found_models = {fm for fm in found_models if fm not in lib_model or len(fm) >= len(lib_model)}
                found_models.add(lib_model)
    final_found_models = list(found_models)
    if DEBUG_MODE: print(f"🕵️‍♂️ Kütüphaneden Model Tespiti (find_models_in_text_from_library): '{user_text}' -> {final_found_models}")
    return final_found_models

def suggest_vehicle_alternative(requested_vehicle, vehicle_df):
    global session_rejected_models, DEBUG_MODE
    aranan_arac_original_case = requested_vehicle
    aranan_arac = str(requested_vehicle).lower().strip()
    direct_availability_columns = ['eş değeri', 'elektrikli', 'öneri3', 'öneri4', 'öneri5']

    if aranan_arac in session_rejected_models and DEBUG_MODE:
        print(f"ℹ️ '{aranan_arac_original_case}' daha önce reddedilmişti, alternatif aranıyor (suggest_vehicle_alternative).")

    for idx, row in vehicle_df.iterrows():
        ceviri_modeli_excel = row.get('çeviri modelleri')
        if ceviri_modeli_excel and aranan_arac == ceviri_modeli_excel:
            es_degeri_excel = row.get('eş değeri')
            if es_degeri_excel and es_degeri_excel not in session_rejected_models:
                return {
                    "durum": 1, "bulunan": ceviri_modeli_excel, "öneri": es_degeri_excel, "excelde_var": True,
                    "mesaj": f"Aradığınız '{str(aranan_arac_original_case).capitalize()}' modeline ({str(ceviri_modeli_excel).capitalize()} olarak kayıtlı) alternatif olarak '{str(es_degeri_excel).capitalize()}' modelini önerebiliriz."}
            elif es_degeri_excel and es_degeri_excel in session_rejected_models and DEBUG_MODE:
                 print(f"ℹ️ '{str(ceviri_modeli_excel).capitalize()}' için eşdeğer '{str(es_degeri_excel).capitalize()}' reddedilmiş.")
            break
    for sutun_adi in direct_availability_columns:
        matching_rows = vehicle_df[vehicle_df[sutun_adi] == aranan_arac]
        if not matching_rows.empty:
            model_in_sutun = matching_rows.iloc[0][sutun_adi]
            if model_in_sutun not in session_rejected_models:
                return {"durum": 2, "bulunan": model_in_sutun, "öneri": model_in_sutun, "excelde_var": True, "mesaj": f"Evet, '{str(model_in_sutun).capitalize()}' modelimiz mevcut. Size bu aracı sunabiliriz."}
            elif DEBUG_MODE:
                print(f"ℹ️ Bulunan '{str(model_in_sutun).capitalize()}' modeli ('{sutun_adi}' sütununda) reddedilenler listesinde.")

    random_pool_columns = ['eş değeri', 'elektrikli', 'öneri3', 'öneri4', 'öneri5']
    potential_random_suggestions_map = {}
    for sutun in random_pool_columns:
        valid_models_in_col = vehicle_df[sutun].dropna().unique()
        for model_aday_lower in valid_models_in_col:
            if model_aday_lower != aranan_arac and model_aday_lower not in session_rejected_models and model_aday_lower is not None:
                if model_aday_lower not in potential_random_suggestions_map:
                     potential_random_suggestions_map[model_aday_lower] = model_aday_lower
    potential_random_suggestions_list = list(potential_random_suggestions_map.values())
    if potential_random_suggestions_list:
        rastgele_oneri = random.choice(potential_random_suggestions_list)
        return {"durum": 3, "bulunan": aranan_arac_original_case, "öneri": rastgele_oneri, "excelde_var": False, "mesaj": f"Aradığınız '{str(aranan_arac_original_case).capitalize()}' modelini şu anda doğrudan portföyümüzde bulamadık. Ancak size alternatif olarak '{str(rastgele_oneri).capitalize()}' modelini önerebiliriz."}
    return {"durum": 4, "bulunan": aranan_arac_original_case, "öneri": None, "excelde_var": False, "mesaj": f"Maalesef '{str(aranan_arac_original_case).capitalize()}' modeli için portföyümüzde size şu anda uygun bir alternatif bulamıyoruz."}

def parse_agent_response_json(response_str: str, agent_name: str = "Agent"):
    if DEBUG_MODE: print(f"📄 {agent_name} Ham Yanıt: {response_str}")
    try:
        data = json.loads(response_str)
        return data
    except json.JSONDecodeError:
        if DEBUG_MODE: print(f"⚠️ {agent_name}: Ham yanıt doğrudan JSON değil, metin içi JSON aranıyor.")
        match_obj = re.search(r'```json\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*```|(\{[\s\S]*?\}|\[[\s\S]*?\])', response_str, re.DOTALL)
        if match_obj:
            json_part = None
            if match_obj.group(1): json_part = match_obj.group(1)
            elif match_obj.group(2): json_part = match_obj.group(2)
            elif match_obj.group(0) and not (match_obj.group(0).startswith("```") and not match_obj.group(0).endswith("```")): json_part = match_obj.group(0)
            if json_part:
                try:
                    data = json.loads(json_part)
                    if DEBUG_MODE: print(f"ℹ️ {agent_name}: Metin içinden JSON başarıyla ayıklandı.")
                    return data
                except json.JSONDecodeError as e_inner:
                    if DEBUG_MODE: print(f"❌ {agent_name}: Ayıklanan bölüm JSON parse edilemedi: '{json_part}'. Hata: {e_inner}")
            elif DEBUG_MODE: print(f"❌ {agent_name}: JSON regex eşleşti ama JSON bölümü boş geldi.")
        if DEBUG_MODE: print(f"❌ {agent_name}: Yanıtta geçerli JSON bloğu bulunamadı.")
        return {"error": f"{agent_name}: Yanıtta JSON bulunamadı veya parse edilemedi", "raw_response": response_str}

async def safe_openrouter_request_async(system_prompt_str, user_prompt_str,
                                        model_name="meta-llama/llama-guard-4-12b",
                                        temperature=0.1, max_tokens=500, expect_json=False):
    global async_client
    if async_client is None: return "API_ERROR: Asenkron istemci başlatılamadı."
    messages = [{"role": "system", "content": system_prompt_str}, {"role": "user", "content": user_prompt_str}]
    request_params = {"model": model_name, "messages": messages, "temperature": temperature, "max_tokens": max_tokens,
                      "extra_headers": {"HTTP-Referer": OPENROUTER_REFERRER, "X-Title": SANITIZED_OPENROUTER_X_TITLE}}
    if expect_json: request_params["response_format"] = {"type": "json_object"}
    if DEBUG_MODE: print(f"\n--- OpenRouter Asenkron İsteği ({model_name}) ---")
    try:
        completion = await async_client.chat.completions.create(**request_params)
        response_content = completion.choices[0].message.content
        if DEBUG_MODE: print(f"✅ OpenRouter Yanıt Alındı ({model_name}).")
        return response_content
    except Exception as e:
        print(f"❌ OpenRouter API Hatası ({model_name}): {e}"); return f"API_ERROR: Model yanıt veremedi ({str(e)})"

def format_structured_history(gecmis_mesajlar_list_param, turns=5):
    if not gecmis_mesajlar_list_param: return "Konuşma geçmişi henüz bulunmamaktadır."
    history_to_format = gecmis_mesajlar_list_param[-(turns*2):]
    history_str_parts = []
    for msg_obj in history_to_format:
        prefix = "User: " if msg_obj["role"] == "user" else "AI: "
        history_str_parts.append(f"{prefix}{msg_obj['content']}")
    return "\n".join(history_str_parts)

LLM_DRIVEN_PROMPTS = {
    "INTENT_ENTITY_EXTRACTOR": """SENARYO: Sen bir metin analiz uzmanısın. Görevin, kullanıcının SON MESAJINDAN ve kısa konuşma geçmişinden ana niyetini ve ilgili varlıkları JSON formatında çıkarmak.

KULLANILABİLİR NİYETLER (Sadece bu listeden birini kullan, EN UYGUN OLANI SEÇ):
- KIMLIK_ONAYLAMA: Kullanıcı kimliğini doğruluyor ("evet", "benim", "doğru" gibi).
- KIMLIK_DUZELTME_ISIM_VERME: Kullanıcı kendi ismini veriyor/düzeltiyor ("hayır ben X Y", "adım Z").
- KIMLIK_REDDETME_GENEL: Kullanıcı sorulan kişi olmadığını genel bir ifadeyle belirtiyor ("hayır değilim", "yanlış numara").
- NEREDEN_ARADINIZ_SORUSU: Kullanıcı nereden/kimin aradığını soruyor ("kimsin", "nereden arıyorsun").
- ARAC_SORGU_YENI: Kullanıcı yeni bir veya daha fazla araç modeli/tipi soruyor, ilgilendiğini belirtiyor (örn: "dizel ne var", "corsa var mı").
- ARAC_SORGU_DETAY_FIYAT: Kullanıcı bir model hakkında teknik detay, fiyat, kampanya vb. soruyor (örn: "corsanın özellikleri neler", "fiyatı ne kadar").
- TEKLIFI_ONAYLAMA: Kullanıcı daha önce AI tarafından yapılan bir araç önerisini, bayi iletişimi teklifini veya bir sonraki adımı onaylıyor (örn: "evet", "tamam", "olur", "kabul ediyorum", "hee", "he", "elbette", "tabii ki", "hı hı"). Onay durumu 'true' olmalı.
- TEKLIFI_REDDETME_ALTERNATIF_ISTEME: Kullanıcı bir önceki öneriyi reddedip alternatif soruyor veya farklı bir model belirtiyor (örn: "hayır onu istemiyorum, bana şunu göster").
- TEKLIFI_REDDETME_KAPATMA: Kullanıcı bir önceki öneriyi reddedip görüşmeyi sonlandırmak istiyor.
- VEDALASMA_KAPATMA: Kullanıcı teşekkür edip görüşmeyi sonlandırıyor.
- ANLAMADIM_TEKRAR_ISTEGI: Kullanıcı bir önceki mesajı anlamadığını belirtip tekrar istiyor.
- KULLANICI_TUTARSIZLIK_ALGILADI: Kullanıcı, AI'ın önceki ifadeleriyle çeliştiğini düşündüğü bir durumu belirtiyor (örn: "az önce yok dedin şimdi var diyorsun", "önce öyle dememiştin").
- GENEL_ONERI_ISTEGI: Kullanıcı genel araç önerisi istiyor ("başka ne var?", "ne önerirsin?", "model tavsiyen var mı?").
- CALISTIGINIZ_MARKALARI_SORMA: Kullanıcı şirketin çalıştığı/elinde bulunan araç markalarını genel olarak soruyor ("hangi markalar var?", "sadece opel mi satıyorsunuz?").
- BELIRSIZ_ALAKASIZ: Yukarıdaki niyetlerden hiçbiri değil veya konu dışı. Kısa, tek kelimelik tepkiler ("hmm", "anladım" gibi) eğer bir teklife doğrudan yanıt değilse bu kategoriye girebilir.

ÇIKARILACAK VARLIKLAR (İlgili olanları doldur, olmayanları null veya boş liste [] olarak bırak. Araç model/marka/tiplerini KÜÇÜK HARFE çevir):
- "modeller": Kullanıcının SON MESAJINDA sorduğu veya bahsettiği araç modellerinin listesi.
- "markalar": Kullanıcının SON MESAJINDA sorduğu araç markalarının listesi.
- "tipler": Kullanıcının SON MESAJINDA sorduğu araç tiplerinin listesi (örn: "elektrikli", "dizel", "suv").
- "isim_soyisim": Kullanıcı kimlik düzeltirken verdiği tam isim (örn: "Ahmet Yılmaz").
- "onay_durumu": Kullanıcı bir teklifi TEKLIFI_ONAYLAMA niyetiyle yanıtlıyorsa true, TEKLIFI_REDDETME_... niyetlerinden biriyle yanıtlıyorsa false. Diğer sorgu veya genel ifadelerde null. ÖNEMLİ: Kullanıcı yeni bir soru soruyorsa (örn: ARAC_SORGU_YENI), bu bir önceki teklife onay/red anlamına gelmez, bu durumda onay_durumu null olmalıdır.

BİLİNEN BAZI ARAÇ MODELLERİ (Doğru tanıma için yardımcı olabilir, sadece bunlarla sınırlı kalma):
{BILINEN_MODEL_LISTESI_KISMI}

Kısa Konuşma Geçmişi (Son birkaç mesaj):
{KONUSMA_GECMISI_KISA}

Kullanıcının Son Mesajı:
{KULLANICI_MESAJI}

Lütfen çıktını SADECE AŞAĞIDAKİ JSON FORMATINDA VER. Başka hiçbir açıklama veya metin ekleme.
{{
  "intent": "NIYET_ETIKETI_BURAYA",
  "entities": {{
    "modeller": [], "markalar": [], "tipler": [], "isim_soyisim": null, "onay_durumu": null
  }},
  "raw_utterance_processed": "{KULLANICI_MESAJI_TEKRAR}"
}}
""",
    "IDENTITY_HANDLER_AGENT": """SENARYO: Sen {COMPANY_NAME} için çalışan bir kimlik yönetimi ve müşteri karşılama uzmanısın. Ana görevin, aranan kişinin doğru kişi olup olmadığını teyit etmek, yanlış kişiyse yeni kişinin kim olduğunu öğrenip onlara genel bir bilgi teklifinde bulunmak, veya doğru kişiyse ve daha önceden bir profil aracı varsa onunla ilgili bilgi sunmaktır.

SİSTEM BİLGİLERİ (Python'dan):
- Hedeflenen Orijinal Profil: {ORIJINAL_PROFIL_BILGISI}
- Profil Aracı Analizi (Kullanıcıya sunulacak mesaj): {PROFIL_ARACI_ANALIZI}
- Önceki AI Sorusu Tipi: {ONCEKI_AI_SORU_TIPI}
- Kullanıcının Son Niyeti (Intent Agent'tan): {DETECTED_INTENT}
- Kullanıcının Son Mesajı: "{KULLANICI_MESAJI}"

GÖREVLERİN:
Kullanıcının niyeti (`DETECTED_INTENT`) ve önceki AI soru tipine (`ONCEKI_AI_SORU_TIPI`) göre aşağıdaki JSON çıktılarından uygun olanı üret.

1.  EĞER `DETECTED_INTENT` == "KIMLIK_REDDETME_GENEL":
    ```json
    {{
      "agent_karari": "KIMLIK_REDDI_YENIDEN_SOR",
      "guncellenmis_isim_soyisim": null,
      "kullanici_yaniti_metni": "Anladım. Peki, bu durumda kiminle görüştüğümü öğrenebilir miyim acaba?",
      "sonraki_python_durumu_onerisi": "KIMLIK_DOGRULAMA_BASLANGIC",
      "ai_sordu_soru_tipi": "KIMLIK_ISIM_SORUSU"
    }}
    ```
2.  EĞER `DETECTED_INTENT` == "KIMLIK_DUZELTME_ISIM_VERME" VE `ONCEKI_AI_SORU_TIPI` == "KIMLIK_ISIM_SORUSU":
    ```json
    {{
      "agent_karari": "YENI_KISI_TANIMLANDI",
      "guncellenmis_isim_soyisim": "[Kullanıcının verdiği yeni tam isim]",
      "kullanici_yaniti_metni": "[Tespit edilen yeni isim], ben {COMPANY_NAME}'dan arıyorum. Size nasıl yardımcı olabilirim?",
      "sonraki_python_durumu_onerisi": "ARAC_ISLEME",
      "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU"
    }}
    ```
3.  EĞER `DETECTED_INTENT` == "KIMLIK_ONAYLAMA":
    (NOT: {PROFIL_ARACI_ANALIZI} Python'dan kullanıcı dostu bir metin olarak gelmeli. Eğer boşsa, genel yardım sorusu sor.)
    ```json
    {{
      "agent_karari": "ONAYLANDI",
      "guncellenmis_isim_soyisim": null,
      "kullanici_yaniti_metni": "Teşekkürler {ORIGINAL_PROFILE_ISIM}. [EĞER {PROFIL_ARACI_ANALIZI} doluysa: {PROFIL_ARACI_ANALIZI} Bu öneriyle ilgilenir misiniz? EĞER {PROFIL_ARACI_ANALIZI} boşsa: Size nasıl yardımcı olabilirim?]",
      "sonraki_python_durumu_onerisi": "ARAC_ISLEME",
      "ai_sordu_soru_tipi": "[Duruma göre ARAC_ILGI_SORUSU veya GENEL_YARDIM_SORUSU]"
    }}
    ```
4.  EĞER `DETECTED_INTENT` == "KIMLIK_DUZELTME_ISIM_VERME" VE `ONCEKI_AI_SORU_TIPI` != "KIMLIK_ISIM_SORUSU":
    ```json
    {{
      "agent_karari": "DUZELTILDI_FARKLI_KISI",
      "guncellenmis_isim_soyisim": "[Kullanıcının verdiği yeni tam isim]",
      "kullanici_yaniti_metni": "Anladım, teşekkürler [Tespit edilen yeni isim]. Ben {COMPANY_NAME}'dan Arda. Size nasıl yardımcı olabilirim?",
      "sonraki_python_durumu_onerisi": "ARAC_ISLEME",
      "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU"
    }}
    ```
""",
    "VEHICLE_INQUIRY_AGENT": """SENARYO: Sen {COMPANY_NAME} için çalışan bir araç bilgi uzmanısın. Görevin, kullanıcının belirli araç modelleri veya tipleri hakkındaki sorularına yanıt vermek.

SİSTEM BİLGİLERİ (Python'dan):
- Müşteri Adı Soyadı (Teyitli): {MUSTERI_ADI_SOYADI_UNVAN}
- Python Araç Analiz Sonuçları (Kullanıcının sorduğu her model/tip için): {PYTHON_ARAC_ANALIZ_SONUCLARI}
- Reddedilen Modeller Listesi: {REDDEDILEN_MODELLER}
- Kullanıcının İlgilendiği Modeller/Tipler: {KULLANICININ_SORDUGU_MODELLER_VE_TIPLER}
- Kullanıcının Son Mesajı: "{KULLANICI_MESAJI}"

GÖREVLERİN:
1. Eğer kullanıcı belirli modeller sorduysa ({KULLANICININ_SORDUGU_MODELLER_VE_TIPLER} içinde model varsa):
   a. Her model için {PYTHON_ARAC_ANALIZ_SONUCLARI}'nı incele.
   b. MEVCUT (Durum 2) ise: "Evet, [Model Adı] mevcut."
   c. EŞDEĞERİ VAR (Durum 1) ise: "[Sorduğu Model] için [Eşdeğer Model] önerebiliriz."
   d. ALTERNATİF VAR (Durum 3) ise: "[Sorduğu Model] yok ama [Alternatif Model] önerebiliriz."
   e. BULUNAMADI (Durum 4) ise: "Maalesef [Sorduğu Model] için bir seçeneğimiz yok."
   f. Birden fazla model varsa, yanıtları birleştir. Sonunda "Bu model(ler)le ilgilenir misiniz?" diye sor.
2. Eğer kullanıcı belirli bir ARAÇ TİPİ sorduysa (örn: "elektrikli araç", "dizel suv", {KULLANICININ_SORDUGU_MODELLER_VE_TIPLER} içinde tip varsa):
   a. {PYTHON_ARAC_ANALIZ_SONUCLARI} içinde bu tipe uygun genel bir öneri metni varsa onu kullan.
   b. Eğer Python özel bir analiz sunmadıysa, genel olarak "Evet, {KULLANICININ_SORDUGU_MODELLER_VE_TIPLER} araçlarımız mevcut. Örneğin portföyümüzdeki [Model A], [Model B] gibi seçeneklerimiz var. Bu tür araçlarla mı ilgileniyorsunuz?" gibi bir yanıt ver. (Model A, B yi portföyden, reddedilmeyenlerden rastgele seç)
3. Portföy dışı bir model için ısrar edilirse, o markayla çalışmadığınızı belirt.
4. Yanıtın kısa ve doğal olmalı. Reddedilen modelleri ASLA önerme.

JSON ÇIKTI FORMATI:
{{
  "kullanici_yaniti_metni": "[Müşteriye verilecek tam yanıt metni]",
  "onerilen_veya_teyit_edilen_modeller_yanitta": ["[Yanıtında MEVCUT OLDUĞUNU TEYİT ETTİĞİN veya AKTİF BİR ALTERNATİF OLARAK SUNDUĞUN modellerin listesi (küçük harf)]"],
  "unavailable_models_queried": ["[Eğer model bulunamadıysa (Durum 4), bulunamayan orijinal modellerin listesi]"],
  "sonraki_python_durumu_onerisi": "TEKLIF_YANITI_BEKLENIYOR",
  "ai_sordu_soru_tipi": "ARAC_ILGI_SORUSU" 
}}
""", # Alternatif sunma onay sorusu da olabilir, agent karar vermeli.
    "GENERAL_RECOMMENDATION_AGENT": """SENARYO: Sen {COMPANY_NAME} için çalışan bir araç öneri uzmanısın. Müşteri genel olarak "başka ne önerirsin?" gibi bir talepte bulundu.

SİSTEM BİLGİLERİ (Python'dan):
- Müşteri Adı Soyadı (Teyitli): {MUSTERI_ADI_SOYADI_UNVAN}
- Python Tarafından Hazırlanan Genel Öneri Listesi (Eğer varsa): {PYTHON_GENEL_ONERI_LISTESI}
- Daha Önce Konuşulan/Reddedilen Modeller: {KONUSULAN_REDDEDILEN_MODELLER}
- Yakın Zamanda Sorulan ve Bulunamayan Modeller Bağlamı: {RECENTLY_UNAVAILABLE_MODELS_CONTEXT}

Kullanıcının Son Mesajı: "{KULLANICI_MESAJI}"

GÖREVLERİN:
1.  Eğer Python bir öneri listesi verdiyse ({PYTHON_GENEL_ONERI_LISTESI}), o listeden 1-2 uygun model seçerek öner.
2.  Eğer {RECENTLY_UNAVAILABLE_MODELS_CONTEXT} bilgisi anlamlıysa ve öneri listenizde bu bilgiyle alakalı bir model varsa, bu durumu açıklayarak önerin.
3.  Emin değilsen veya uygun model bulamazsan, müşteriye hangi segmentte veya özelliklerde araç aradığını sor.
4.  Yanıtın ÇOK KISA ve doğal olmalı.
JSON ÇIKTI FORMATI:
{{
  "kullanici_yaniti_metni": "[Müşteriye verilecek tam yanıt metni]",
  "onerilen_modeller_yanitta": ["[Yanıtında önerdiğin modellerin listesi (küçük harf)]"],
  "sonraki_python_durumu_onerisi": "TEKLIF_YANITI_BEKLENIYOR",
  "ai_sordu_soru_tipi": "ARAC_ILGI_SORUSU"
}}
""",
"OFFER_RESPONSE_HANDLER_AGENT": """SENARYO: Sen {COMPANY_NAME} için çalışan bir satış destek uzmanısın. Bir önceki turda müşteriye bir teklifte bulunuldu (örn: bayi araması, belirli bir modelle ilgilenip ilgilenmediği soruldu) ve müşteri bu teklife yanıt verdi. ÖNEMLİ: Bu agent SADECE kullanıcı AI'ın bir önceki sorusuna/teklifine DOĞRUDAN yanıt veriyorsa (onay, red, vs.) çağrılmalıdır. Eğer kullanıcı yeni bir araç sorgusu yapıyorsa veya konuyla alakasız bir şey söylüyorsa, Orkestratör bu durumu farklı ele almalı ve bu agent'ı çağırmamalıdır.

SİSTEM BİLGİLERİ (Python'dan):
- Müşteri Adı Soyadı (Teyitli): {MUSTERI_ADI_SOYADI_UNVAN}
- Bir Önceki AI Sorusu Tipi: {ONCEKI_AI_SORU_TIPI}
- Önceki Turda Konuşulan/Teklif Edilen Modeller: {ONCEKI_TUR_MODELLERI}
- Python Tarafından Sağlanan Alternatifler Metni (Eğer {ONCEKI_AI_SORU_TIPI} == "ALTERNATIF_SUNMA_ONAY_SORUSU" ise ve onaylandıysa): {PYTHON_PROVIDED_ALTERNATIVES_TEXT}

Kullanıcının Son Mesajı (Teklife Yanıtı): "{KULLANICI_MESAJI}"
Niyet Agent'ı Çıktısı (Kullanıcının yanıtının niyeti): {NIYET_AGENT_CIKTISI}

GÖREVLERİN (Sırayla değerlendir):

1.  **KULLANICI TEKLİFİ ONAYLADIYSA (`{NIYET_AGENT_CIKTISI}.entities.onay_durumu == true`):**
    a.  EĞER `{ONCEKI_AI_SORU_TIPI}` == "ALTERNATIF_SUNMA_ONAY_SORUSU" VE `{PYTHON_PROVIDED_ALTERNATIVES_TEXT}` anlamlıysa:
        ```json
        {{ "kullanici_yaniti_metni": "{PYTHON_PROVIDED_ALTERNATIVES_TEXT} Bu modellerle ilgilenir misiniz?", "teklif_onay_durumu_python_icin": true, "reddedilen_modeller_bu_tur": [], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "TEKLIF_YANITI_BEKLENIYOR", "ai_sordu_soru_tipi": "ARAC_ILGI_SORUSU" }}
        ```
    b.  EĞER `{ONCEKI_AI_SORU_TIPI}` == "BAYI_ONAY_SORUSU":
        ```json
        {{ "kullanici_yaniti_metni": "Harika! Yetkili bayimiz [{ONCEKI_TUR_MODELLERI} hakkında] en kısa sürede sizinle iletişime geçecektir. Başka bir konuda yardımcı olabilir miyim?", "teklif_onay_durumu_python_icin": true, "reddedilen_modeller_bu_tur": [], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "ARAC_ISLEME", "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU" }}
        ```
    c.  EĞER `{ONCEKI_AI_SORU_TIPI}` == "ARAC_ILGI_SORUSU":
        ```json
        {{ "kullanici_yaniti_metni": "Anladım, [{ONCEKI_TUR_MODELLERI} listesindeki İLK MODELİ yaz] ile ilgileniyorsunuz. Bu model için sizi yetkili bayimizin aramasını organize etmemi ister misiniz?", "teklif_onay_durumu_python_icin": true, "reddedilen_modeller_bu_tur": [], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "TEKLIF_YANITI_BEKLENIYOR", "ai_sordu_soru_tipi": "BAYI_ONAY_SORUSU" }}
        ```
    d.  EĞER `{ONCEKI_AI_SORU_TIPI}` == "BAYI_MODEL_TEYIT_SORUSU" VE `{NIYET_AGENT_CIKTISI}.entities.modeller` doluysa:
        ```json
        {{ "kullanici_yaniti_metni": "Tamamdır, [{NIYET_AGENT_CIKTISI}.entities.modeller içindeki ilk model] için bayi araması organize ediyorum. En kısa sürede sizinle iletişime geçecekler. Başka bir konuda yardımcı olabilir miyim?", "teklif_onay_durumu_python_icin": true, "reddedilen_modeller_bu_tur": [], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "ARAC_ISLEME", "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU" }}
        ```
    e.  DİĞER ONAY DURUMLARI (örn: `{ONCEKI_AI_SORU_TIPI}` == "BAYI_MODEL_TEYIT_SORUSU" ama kullanıcı model belirtmediyse veya genel bir onaysa):
        ```json
        {{ "kullanici_yaniti_metni": "Anladım, bir bayi yönlendirmesi konusunda size yardımcı olmamı istiyorsunuz. Hangi belirli model veya modeller için yetkili bayimizin sizinle iletişime geçmesini istersiniz?", "teklif_onay_durumu_python_icin": true, "reddedilen_modeller_bu_tur": [], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "TEKLIF_YANITI_BEKLENIYOR", "ai_sordu_soru_tipi": "BAYI_MODEL_TEYIT_SORUSU" }}
        ```
2.  **KULLANICI TEKLİFİ REDDETTİYSE (`{NIYET_AGENT_CIKTISI}.entities.onay_durumu == false`):**
    a.  EĞER (`{NIYET_AGENT_CIKTISI}.intent == "TEKLIFI_REDDETME_ALTERNATIF_ISTEME"` VEYA `{NIYET_AGENT_CIKTISI}.intent == "ARAC_SORGU_YENI"`) VE (`{NIYET_AGENT_CIKTISI}.entities.modeller` VEYA `{NIYET_AGENT_CIKTISI}.entities.tipler`) doluysa (Yani kullanıcı reddedip yeni bir şey sorduysa):
        ```json
        {{
          "kullanici_yaniti_metni": null,
          "teklif_onay_durumu_python_icin": false, 
          "reddedilen_modeller_bu_tur": ["[Eğer {ONCEKI_TUR_MODELLERI} listesi doluysa, içindeki modelleri buraya küçük harfle, HER BİRİNİ AYRI STRİNG OLARAK LİSTE İÇİNDE yaz.]"],
          "kullanicinin_yeni_sordugu_modeller": ["[Niyet Agent çıktısındaki ({NIYET_AGENT_CIKTISI}) 'entities.modeller' veya 'entities.tipler' listesindeki tüm öğeleri buraya ekle]"],
          "sonraki_python_durumu_onerisi": "ARAC_ISLEME_DIREKT_SORGULA",
          "ai_sordu_soru_tipi": "SORU_YOK"
        }}
        ```
    b.  EĞER `{NIYET_AGENT_CIKTISI}.intent == "TEKLIFI_REDDETME_KAPATMA"`:
        ```json
        {{ "kullanici_yaniti_metni": "Anlıyorum. Vakit ayırdığınız için teşekkürler, iyi günler dilerim.", "teklif_onay_durumu_python_icin": false, "reddedilen_modeller_bu_tur": ["[Eğer {ONCEKI_TUR_MODELLERI} listesi doluysa, içindeki modelleri buraya küçük harfle, HER BİRİNİ AYRI STRİNG OLARAK LİSTE İÇİNDE yaz.]"], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "VEDALASMA_ISLEME", "ai_sordu_soru_tipi": "SORU_YOK" }}
        ```
    c.  DİĞER REDDETME DURUMLARI (örn: genel red, alternatif isteme ama yeni model belirtmeme):
        ```json
        {{ "kullanici_yaniti_metni": "Anladım. Peki, farklı bir model mi düşünürsünüz yoksa başka bir konuda yardımcı olabilir miyim?", "teklif_onay_durumu_python_icin": false, "reddedilen_modeller_bu_tur": ["[Eğer {ONCEKI_TUR_MODELLERI} listesi doluysa, içindeki modelleri buraya küçük harfle, HER BİRİNİ AYRI STRİNG OLARAK LİSTE İÇİNDE yaz.]"], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "ARAC_ISLEME", "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU" }}
        ```
3.  **EĞER YUKARIDAKİ KOŞULLARIN HİÇBİRİ UYMUYORSA (BELİRSİZ YANIT):**
    ```json
    {{
      "kullanici_yaniti_metni": "Üzgünüm, tam olarak anlayamadım. Önceki teklifimizle ilgili miydi, yoksa farklı bir konuda mı yardımcı olmamı istersiniz?",
      "teklif_onay_durumu_python_icin": null,
      "reddedilen_modeller_bu_tur": [],
      "kullanicinin_yeni_sordugu_modeller": [],
      "sonraki_python_durumu_onerisi": "TEKLIF_YANITI_BEKLENIYOR", 
      "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU"
    }}
    ```
JSON ÇIKTI FORMATI (yukarıdaki örneklerde belirtildiği gibi):
{{
  "kullanici_yaniti_metni": "[...]", "teklif_onay_durumu_python_icin": true/false/null, "reddedilen_modeller_bu_tur": [], "kullanicinin_yeni_sordugu_modeller": [], "sonraki_python_durumu_onerisi": "[...]", "ai_sordu_soru_tipi": "[...]"
}}
""",
    "FAREWELL_AGENT": """SENARYO: Sen {COMPANY_NAME} için çalışan nazik bir asistansın. Kullanıcı görüşmeyi sonlandırmak istiyor veya konuşulacak başka bir konu kalmadı.
SİSTEM BİLGİLERİ (Python'dan):
- Müşteri Adı Soyadı (Teyitli veya Orijinal): {MUSTERI_ADI_SOYADI_UNVAN}
Kullanıcının Son Mesajı: "{KULLANICI_MESAJI}"
Niyet Agent'ı Çıktısı: {NIYET_AGENT_CIKTISI}
GÖREVİN: Kibarca teşekkür et ve iyi günler dile.
JSON ÇIKTI FORMATI:
{{
  "kullanici_yaniti_metni": "[Müşteriye verilecek veda mesajı]",
  "sonraki_python_durumu_onerisi": "GORUSMEYI_BITIR",
  "ai_sordu_soru_tipi": "SORU_YOK"
}}
""",
    "FALLBACK_AGENT": """SENARYO: Sen {COMPANY_NAME} için çalışan yardımcı bir asistansın. Kullanıcının son söylediği net anlaşılamadı veya sistemin şu an ele alamayacağı bir durum oluştu.
SİSTEM BİLGİLERİ (Python'dan):
- Müşteri Adı Soyadı (Teyitli veya Orijinal): {MUSTERI_ADI_SOYADI_UNVAN}
- Kısa Konuşma Geçmişi: {KONUSMA_GECMISI_FALLBACK}
- AI'ın Önceki Açıklaması (Eğer varsa): {RECENTLY_UNAVAILABLE_MODELS_AI_EXPLANATION}
Kullanıcının Son Mesajı: "{KULLANICI_MESAJI}"
Niyet Agent'ı Çıktısı: {NIYET_AGENT_CIKTISI}
GÖREVİN:
1.  EĞER `{NIYET_AGENT_CIKTISI}.intent == "KULLANICI_TUTARSIZLIK_ALGILADI"` İSE:
    Kullanıcının mesajını dikkate alarak durumu açıkla: "{KULLANICI_MESAJI}" demiştiniz. Haklısınız, bir karışıklık olmuş olabilir. Durumu netleştireyim: [{RECENTLY_UNAVAILABLE_MODELS_AI_EXPLANATION}]. Amacım size en uygun seçenekleri sunmaktır. Hangi modelle ilgili bilgi almak istersiniz ya da nasıl yardımcı olabilirim?"
2.  EĞER `{NIYET_AGENT_CIKTISI}.intent == "ANLAMADIM_TEKRAR_ISTEGI"` İSE: Önceki AI mesajını farklı kelimelerle tekrar et veya genel yardım sor.
3.  EĞER `{NIYET_AGENT_CIKTISI}.intent == "BELIRSIZ_ALAKASIZ"` İSE: Genel yardım sorusu sor veya konuya dönmesini iste.
4.  EĞER `{NIYET_AGENT_CIKTISI}.intent == "CALISTIGINIZ_MARKALARI_SORMA"` İSE:
    Yanıt: "{MUSTERI_ADI_SOYADI_UNVAN}, {COMPANY_NAME} olarak portföyümüzde bulunan başlıca markalar: {CALISILAN_MARKALAR_STR}. Özellikle ilgilendiğiniz bir marka veya model var mıdır?" (Eğer {CALISILAN_MARKALAR_STR} boşsa, "birçok popüler marka" yerine "çeşitli markalarda araçlarımız mevcut" de.)
JSON ÇIKTI FORMATI:
{{
  "kullanici_yaniti_metni": "[Müşteriye verilecek yanıt]",
  "sonraki_python_durumu_onerisi": "[Mevcut Python durumunu koru veya ARAC_ISLEME]",
  "ai_sordu_soru_tipi": "GENEL_YARDIM_SORUSU"
}}
"""
}

async def get_intent_and_entities(user_message: str, short_history: str, known_models_sample: list):
    global async_client, DEBUG_MODE
    if not async_client: return {"intent": "BELIRSIZ_ALAKASIZ", "entities": {}, "error": "Asenkron istemci başlatılamadı", "raw_utterance_processed": user_message}
    sample_size = 30
    if len(known_models_sample) > sample_size:
        bilinen_modeller_str = ", ".join(random.sample(known_models_sample, sample_size)) + ", ..."
    else:
        bilinen_modeller_str = ", ".join(known_models_sample)
    prompt_user_for_intent = LLM_DRIVEN_PROMPTS["INTENT_ENTITY_EXTRACTOR"].format(
        BILINEN_MODEL_LISTESI_KISMI=bilinen_modeller_str,
        KONUSMA_GECMISI_KISA=short_history,
        KULLANICI_MESAJI=user_message,
        KULLANICI_MESAJI_TEKRAR=user_message
    )
    system_p = "You are an expert text analysis assistant. Your task is to extract intent and entities from the user's message based on the provided guidelines and output a JSON object."
    if DEBUG_MODE: print(f"\n🕵️ Niyet/Varlık Agent User Prompt (Kısmi):\n{prompt_user_for_intent[:600]}...")
    response_str = await safe_openrouter_request_async(
        system_prompt_str=system_p, user_prompt_str=prompt_user_for_intent,
        model_name="meta-llama/llama-guard-4-12b", temperature=0.0, max_tokens=400, expect_json=True
    )
    if "API_ERROR" in response_str:
        return {"intent": "BELIRSIZ_ALAKASIZ", "entities": {}, "error": response_str, "raw_utterance_processed": user_message}
    parsed_data = parse_agent_response_json(response_str, "Niyet/Varlık Agent")
    if "error" in parsed_data:
        return {"intent": "BELIRSIZ_ALAKASIZ", "entities": {}, "error": parsed_data["error"], "raw_utterance_processed": user_message, "raw_response": parsed_data.get("raw_response")}
    if not (isinstance(parsed_data, dict) and "intent" in parsed_data and "entities" in parsed_data):
        if DEBUG_MODE: print(f"❌ Niyet/Varlık Agent Yanıtında Gerekli Alanlar Yok: {parsed_data}")
        return {"intent": "BELIRSIZ_ALAKASIZ", "entities": {}, "error": "Ayrıştırılan JSON'da niyet/varlıklar eksik", "raw_utterance_processed": user_message, "raw_response": response_str if isinstance(response_str, str) else json.dumps(response_str)}
    entities = parsed_data.get("entities", {})
    if not isinstance(entities, dict):
        if DEBUG_MODE: print(f"⚠️ Niyet/Varlık: 'entities' alanı dict değil, şu bulundu: {entities}. Boş dict ile değiştiriliyor.")
        entities = {}
        parsed_data["entities"] = entities
    for key in ["modeller", "markalar", "tipler"]:
        if key in entities and not isinstance(entities[key], list):
            if DEBUG_MODE: print(f"⚠️ Niyet/Varlık: '{key}' alanı liste değil, string bulundu: {entities[key]}. Tek elemanlı listeye çevriliyor.")
            entities[key] = [str(entities[key])] if entities[key] is not None and str(entities[key]).strip() != "" else []
        elif key not in entities:
             entities[key] = []
    if "onay_durumu" in entities and not isinstance(entities["onay_durumu"], bool) and entities["onay_durumu"] is not None:
        if isinstance(entities["onay_durumu"], str):
            val_lower = entities["onay_durumu"].lower()
            if val_lower == 'true': entities["onay_durumu"] = True
            elif val_lower == 'false': entities["onay_durumu"] = False
            else: entities["onay_durumu"] = None
        elif isinstance(entities["onay_durumu"], int):
            entities["onay_durumu"] = bool(entities["onay_durumu"])
        else: entities["onay_durumu"] = None
    parsed_data["entities"] = entities
    if DEBUG_MODE: print(f"🕵️ Niyet/Varlık Agent Sonucu (İşlenmiş): {parsed_data}")
    return parsed_data

async def execute_task_agent(agent_name_key: str, prompt_format_values: dict,
                             default_model="meta-llama/llama-guard-4-12b",
                             temperature=0.1, max_tokens=400):
    global async_client, DEBUG_MODE, COMPANY_NAME
    if not async_client: return {"error": "Asenkron istemci başlatılamadı", "agent_name_key_executed": agent_name_key}
    agent_prompt_template = LLM_DRIVEN_PROMPTS.get(agent_name_key)
    if not agent_prompt_template:
        return {"error": f"{agent_name_key} için agent prompt şablonu bulunamadı.", "agent_name_key_executed": agent_name_key}
    prompt_format_values.setdefault("COMPANY_NAME", COMPANY_NAME)
    prompt_format_values.setdefault("PYTHON_PROVIDED_ALTERNATIVES_TEXT", "İlgili bir alternatif metni bulunamadı.")
    prompt_format_values.setdefault("RECENTLY_UNAVAILABLE_MODELS_CONTEXT", "Yakın zamanda bulunamayan model bilgisi yok.")
    prompt_format_values.setdefault("RECENTLY_UNAVAILABLE_MODELS_AI_EXPLANATION", "Daha önce yapılmış bir AI açıklaması yok.")
    prompt_format_values.setdefault("CALISILAN_MARKALAR_STR", "birçok popüler marka")
    try:
        full_prompt_for_agent = agent_prompt_template.format(**prompt_format_values)
    except KeyError as e:
        if DEBUG_MODE: print(f"❌ {agent_name_key} prompt formatlamada eksik anahtar: {e}. Mevcut anahtarlar: {list(prompt_format_values.keys())}")
        return {"error": f"Prompt formatlamada eksik anahtar: {e}", "agent_name_key_executed": agent_name_key}
    generic_system_prompt = "You are a specialized AI assistant for a vehicle sales company. Follow the instructions in the user prompt carefully and provide your response ONLY in the specified JSON format. Be concise and helpful."
    if DEBUG_MODE:
        print(f"\n🤖 {agent_name_key} Agent'ına Gönderilen Prompt (Kısmi):")
        print(full_prompt_for_agent[:700] + "...")
    response_str = await safe_openrouter_request_async(
        system_prompt_str=generic_system_prompt, user_prompt_str=full_prompt_for_agent,
        model_name=default_model, temperature=temperature, max_tokens=max_tokens, expect_json=True
    )
    if "API_ERROR" in response_str:
        if DEBUG_MODE: print(f"❌ {agent_name_key} Agent API Hatası: {response_str}")
        return {"error": response_str, "agent_name_key_executed": agent_name_key}
    parsed_data = parse_agent_response_json(response_str, agent_name_key)
    parsed_data["agent_name_key_executed"] = agent_name_key
    if DEBUG_MODE: print(f"🤖 {agent_name_key} Agent Sonucu: {parsed_data}")
    return parsed_data

def kaydet_onaylar_guncellenmis(user_id, isim, soyisim, onay_verisi_dict):
    # ... (Bu fonksiyon değişmedi) ...
    if DEBUG_MODE: print(f"💾 Kaydedilecek Onay/Ret Verisi: User ID: {user_id}, İsim: {isim} {soyisim}, Araç: {onay_verisi_dict.get('marka')} {onay_verisi_dict.get('model')}, Durum: {onay_verisi_dict.get('durum')}, Lokasyon: {onay_verisi_dict.get('sehir')}/{onay_verisi_dict.get('ilce')}")
    log_onay_path = Path("onay_red_kayitlari.csv")
    file_exists = log_onay_path.exists()
    fieldnames = ["timestamp", "user_id", "isim", "soyisim", "marka", "model", "durum", "sehir", "ilce"]
    entry_to_save = {
        "timestamp": datetime.now().isoformat(), "user_id": user_id, "isim": isim, "soyisim": soyisim,
        "marka": onay_verisi_dict.get("marka"), "model": onay_verisi_dict.get("model"),
        "durum": onay_verisi_dict.get("durum"), "sehir": onay_verisi_dict.get("sehir"), "ilce": onay_verisi_dict.get("ilce")
    }
    try:
        with log_onay_path.open("a", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists or f.tell() == 0:
                writer.writeheader()
            writer.writerow(entry_to_save)
        if DEBUG_MODE: print(f"✅ Onay/Ret verisi '{log_onay_path}' dosyasına eklendi.")
    except Exception as e: print(f"❌ Onay/Ret verisi CSV'ye yazılırken hata: {e}")


async def analiz_et_ve_kaydet_veritabani_async(konusma_gecmisi_str: str, user_id: str, user_final_details: dict):
    # ... (Bu fonksiyon değişmedi) ...
    global DEBUG_MODE, async_client
    if DEBUG_MODE: print(f"\n📊 Son Analiz Agent ile Onay/Ret Tespiti Başlatılıyor...")
    sehir = user_final_details.get('sehir', 'Bilinmiyor')
    ilce = user_final_details.get('ilce', 'Bilinmiyor')
    analiz_user_prompt_onay_ret = f"""
Sen bir analiz asistanısın. Aşağıdaki çağrı merkezi görüşme geçmişini dikkatlice incele.
Görüşmede adı geçen ve müşteri tarafından bilgi almak için ONAYLANAN veya REDDEDİLEN (onaylanmayan/vazgeçilen/ilgi gösterilmeyen) her araç modelini tespit et.
- Eğer müşteri belirli bir model hakkında bayi tarafından aranmayı veya daha fazla bilgi almayı net bir şekilde ONAYLADIYSA, "durum": "onaylandı" yaz.
- Eğer müşteri belirli bir modele ilgi göstermediyse, reddettiyse veya alternatif arayışına girdiyse, "durum": "onaylanmadı" yaz.
- Sadece konuşma sonunda müşterinin nihai olarak onayladığı veya reddettiği durumları listele. Araştırılan ama sonuca bağlanmayan modelleri dahil etme.
- Sonucu aşağıdaki JSON formatında bir liste olarak döndür. Her bir araç için ayrı bir JSON nesnesi oluştur.
- JSON nesnesine kullanıcının şehir ve ilçe bilgisini de ekle.
Format:
[
  {{"marka": "[Marka Adı]", "model": "[Model Adı]", "durum": "onaylandı", "sehir": "{sehir}", "ilce": "{ilce}"}},
  {{"marka": "[Diğer Marka]", "model": "[Diğer Model]", "durum": "onaylanmadı", "sehir": "{sehir}", "ilce": "{ilce}"}}
]
Eğer net bir nihai onay veya ret yoksa, boş bir liste döndür: []
Görüşme geçmişi:
{konusma_gecmisi_str}"""
    analiz_system_prompt = "Sen bir görüşme analiz asistanısın. Konuşmayı analiz edip, müşterinin hangi araçlar için bilgi almayı onayladığını veya reddettiğini JSON formatında bir liste olarak çıkarırsın."
    if DEBUG_MODE: print(f"\n📊 Son Analiz Agent Prompt (Onay/Ret):\n{analiz_user_prompt_onay_ret[:700]}...")
    response_content = await safe_openrouter_request_async(
        system_prompt_str=analiz_system_prompt, user_prompt_str=analiz_user_prompt_onay_ret,
        model_name="meta-llama/llama-guard-4-12b", temperature=0.0, max_tokens=1024, expect_json=True)
    if "API_ERROR" in response_content:
        print(f"❌ Son Onay/Ret Analiz API hatası: {response_content}"); return
    if DEBUG_MODE: print(f"\n📊 Son Analiz Agent Ham Dönüşü (Onay/Ret):\n{response_content}")
    json_liste = parse_agent_response_json(response_content, "Son Onay/Ret Analiz Agent")
    if isinstance(json_liste, dict) and "error" in json_liste:
        print(f"❌ Son Onay/Ret Analiz Pars Etme Hatası: {json_liste.get('error')}")
        if DEBUG_MODE and "raw_response" in json_liste: print(f"  Ham yanıt: {json_liste['raw_response']}")
        return
    if not isinstance(json_liste, list):
        print(f"❌ Son Onay/Ret Analiz yanıtı beklenen liste formatında değil, alınan: {type(json_liste)}. Yanıt: {json_liste}")
        json_liste = []
    if not json_liste and DEBUG_MODE: print("ℹ️ Son analizde onaylanan/reddedilen araç bulunamadı.")
    for onay_verisi in json_liste:
        if isinstance(onay_verisi, dict) and all(k in onay_verisi for k in ["marka", "model", "durum"]):
            onay_verisi.setdefault("sehir", sehir); onay_verisi.setdefault("ilce", ilce)
            kaydet_onaylar_guncellenmis(user_id, user_final_details.get("isim", "Bilinmiyor"), user_final_details.get("soyisim", ""), onay_verisi)
        elif DEBUG_MODE:
            print(f"⚠️ Son Analiz: Eksik formatta onay verisi atlandı: {onay_verisi}")

def get_unique_brands_from_models(df_vehicles_input: pd.DataFrame,
                                  recommendation_columns: list = None,
                                  output_dir: str = "arac_analizi_raporlari",
                                  save_files: bool = False) -> list:
    # ... (Bu fonksiyon değişmedi, ileride kullanılacak) ...
    global DEBUG_MODE
    if df_vehicles_input is None or df_vehicles_input.empty:
        if DEBUG_MODE: print("Hata: get_unique_brands_from_models - Giriş DataFrame'i boş veya None.")
        return []
    if recommendation_columns is None:
        recommendation_columns = ['eş değeri', 'elektrikli', 'öneri3', 'öneri4', 'öneri5']
    if save_files:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            if DEBUG_MODE: print(f"\n'{output_dir}' dizini oluşturuldu.")
    all_unique_models_from_recommendations = set()
    for col_name in recommendation_columns:
        if col_name in df_vehicles_input.columns:
            unique_models_in_col = df_vehicles_input[col_name].dropna().astype(str).str.strip()
            unique_models_in_col = unique_models_in_col[unique_models_in_col.str.lower() != 'none']
            unique_models_in_col = unique_models_in_col[unique_models_in_col != ''].unique()
            all_unique_models_from_recommendations.update(unique_models_in_col)
            if save_files and len(unique_models_in_col) > 0:
                df_unique_col_models = pd.DataFrame(sorted(list(unique_models_in_col)), columns=['unique_vehicle_model'])
                safe_col_name = re.sub(r'[^a-zA-Z0-9_]', '', col_name)
                output_col_filename = os.path.join(output_dir, f"benzersiz_onerilen_modeller_{safe_col_name}.csv")
                try:
                    df_unique_col_models.to_csv(output_col_filename, index=False, encoding='utf-8')
                except Exception as e:
                    if DEBUG_MODE: print(f"HATA: {output_col_filename} dosyası yazılırken sorun oluştu: {e}")
        elif DEBUG_MODE:
            print(f"Uyarı: '{col_name}' sütunu öneri analizi için DataFrame'de bulunamadı.")
    derived_brands = set()
    for model_name_full in all_unique_models_from_recommendations:
        model_name = str(model_name_full).strip()
        if model_name:
            brand_candidate = model_name.split(' ')[0].lower()
            if brand_candidate:
                derived_brands.add(brand_candidate.capitalize())
    sorted_unique_brands = sorted(list(derived_brands))
    if save_files and sorted_unique_brands:
        df_final_unique_brands = pd.DataFrame(sorted_unique_brands, columns=['unique_brand_name'])
        output_brands_filename = os.path.join(output_dir, "tum_benzersiz_turetilmis_markalar.csv")
        try:
            df_final_unique_brands.to_csv(output_brands_filename, index=False, encoding='utf-8')
        except Exception as e:
            if DEBUG_MODE: print(f"HATA: {output_brands_filename} dosyası yazılırken sorun oluştu: {e}")
    elif save_files and not sorted_unique_brands and DEBUG_MODE:
        print("Kaydedilecek türetilmiş benzersiz marka bulunamadı.")
    return sorted_unique_brands

async def main_async_llm_driven():
    global session_rejected_models, fuzzy_matching_model_library_list, DEBUG_MODE, async_client, konusma_gecmisi_log_tamami, COMPANY_NAME, df_vehicles

    debug_input = input("Debug modunu aktif etmek ister misiniz? (evet/hayır): ").lower()
    DEBUG_MODE = True if debug_input == "evet" else False
    print(f"--- DEBUG MODU {'AKTİF' if DEBUG_MODE else 'KAPALI'} ---")

    if not load_external_model_library_from_csv():
        print("UYARI: Harici model kütüphanesi yüklenemedi. Model tanıma yetenekleri sınırlı olabilir.")

    print("📞 Aramak istediğin kişinin ID'sini seç:")
    for i, user_profile_item in enumerate(kullanicilar):
        print(f"{i}: {user_profile_item['isim']} {user_profile_item['soyisim']} - {user_profile_item.get('marka','Marka Yok')} {user_profile_item.get('model','Model Yok')}")

    selected_id_str = input("ID gir: ")
    try:
        original_user_profile = next((u for u in kullanicilar if u["id"] == selected_id_str), None)
        if not original_user_profile:
            selected_id_int_fallback = int(selected_id_str)
            if 0 <= selected_id_int_fallback < len(kullanicilar):
                original_user_profile = kullanicilar[selected_id_int_fallback]
            else: raise ValueError("ID bulunamadı")
    except (ValueError, IndexError):
        print("❌ Geçersiz ID. Program sonlandırılıyor."); return

    current_user_details = original_user_profile.copy()
    current_user_details['original_isim'] = original_user_profile['isim']
    current_user_details['original_soyisim'] = original_user_profile['soyisim']
    current_user_details["isim_teyit_edildi"] = False
    current_user_details['pending_models_for_alternatives'] = []
    current_user_details['recently_unavailable_direct_query_info'] = None

    session_rejected_models = []
    konusma_gecmisi_log_tamami = ""
    gecmis_mesajlar_list_llm_icin = []

    current_orchestrator_state = "KIMLIK_DOGRULAMA_BASLANGIC"
    ai_last_question_type = "KIMLIK_TEYIT_SORUSU"

    _intent_for_next_turn = None
    _entities_for_next_turn = None
    _user_input_for_next_turn_context = None
    session_last_offered_models = []

    user_isim_unvan_ilk = f"{current_user_details['isim']} {current_user_details.get('unvan', get_unvan(current_user_details['isim']))}"

    selamlama_system_prompt = f"You are a call center assistant for {COMPANY_NAME}, a new vehicle sales company. Your task is to make the initial greeting. You are calling the customer for the first time."
    selamlama_user_prompt = f"Politely introduce that you are calling from {COMPANY_NAME}. Then, directly ask to confirm if the person you have called is indeed '{user_isim_unvan_ilk}'. For example, the question part in Turkish should be similar to '... {user_isim_unvan_ilk} ile mi görüşüyorum?'. Your entire response must be a single, short, and natural-sounding sentence in Turkish."
    ai_message_text = await safe_openrouter_request_async(
        system_prompt_str=selamlama_system_prompt, user_prompt_str=selamlama_user_prompt,
        model_name="meta-llama/llama-guard-4-12b", temperature=0.3, max_tokens=100 )
    fallback_greeting = f"Merhaba, {COMPANY_NAME}'dan arıyorum. {user_isim_unvan_ilk} ile mi görüşüyorum?"
    if "API_ERROR" in ai_message_text or not ai_message_text.strip():
        ai_message_text = fallback_greeting
        if DEBUG_MODE: print(f"⚠️ LLM ilk selamlama için yanıt veremedi, fallback kullanılıyor.")
    else:
        ai_message_text = ai_message_text.strip().split('\n')[0]
        user_name_check = original_user_profile['isim']
        if (f"ben {user_name_check.lower()}" in ai_message_text.lower() and ai_message_text.endswith("?")) or \
           (f"adım {user_name_check.lower()}" in ai_message_text.lower() and ai_message_text.endswith("?")) or \
           (f" {user_name_check.lower()}'im mi" in ai_message_text.lower()) or \
           (f" {user_name_check.lower()} miyim" in ai_message_text.lower()):
            if DEBUG_MODE: print(f"⚠️ LLM ilk selamlamada hatalı kimlik sorgusu yaptı ('{ai_message_text}'), fallback kullanılıyor.")
            ai_message_text = fallback_greeting

    print(f"\n{datetime.now().strftime('%H:%M:%S')} 🧠 AI: {ai_message_text}")
    konusma_gecmisi_log_tamami += f"AI: {ai_message_text}"
    gecmis_mesajlar_list_llm_icin.append({"role": "assistant", "content": ai_message_text})
    user_input_text = ""

    while True:
        if DEBUG_MODE:
            print(f"\n🔄 ORKESTRATÖR TUR BAŞI: Durum: {current_orchestrator_state} | Reddedilenler: {session_rejected_models} | Önceki AI Soru: {ai_last_question_type} | Bekleyen Alt Sorgu: {current_user_details.get('pending_models_for_alternatives')}")
            print(f"    _intent_for_next_turn: {_intent_for_next_turn}, _entities_for_next_turn: {_entities_for_next_turn}, _user_input_for_next_turn_context: '{_user_input_for_next_turn_context}'")
            print(f"    session_last_offered_models: {session_last_offered_models}")
            print(f"    current_user_details['recently_unavailable_direct_query_info']: {current_user_details.get('recently_unavailable_direct_query_info')}")

        user_input_text_this_turn = ""
        intent_entity_result = {}
        user_input_text_to_use_in_prompt = ""
        detected_intent = "BELIRSIZ_ALAKASIZ"
        detected_entities = {"modeller": [], "markalar": [], "tipler": [], "isim_soyisim": None, "onay_durumu": None}

        if current_orchestrator_state in ["ARAC_ISLEME_DIREKT_SORGULA", "GENEL_ONERI_ISTEGI_DIREKT_SUN"] and _intent_for_next_turn:
            if DEBUG_MODE: print(f"ℹ️ Direkt aksiyon durumu: {current_orchestrator_state}. Önceden ayarlanmış niyet ('{_intent_for_next_turn}') ve varlıklar kullanılacak.")
            detected_intent = _intent_for_next_turn
            detected_entities = _entities_for_next_turn if _entities_for_next_turn else detected_entities
            user_input_text_to_use_in_prompt = _user_input_for_next_turn_context if _user_input_for_next_turn_context else "Doğrudan eylem."
            intent_entity_result = {"intent": detected_intent, "entities": detected_entities, "raw_utterance_processed": user_input_text_to_use_in_prompt}
            if DEBUG_MODE: print(f"    Direkt aksiyon için hazırlanan intent_entity_result: {intent_entity_result}")
            _intent_for_next_turn = None
            _entities_for_next_turn = None
            _user_input_for_next_turn_context = None
        else:
            current_user_display_name = f"{current_user_details['isim']} {current_user_details.get('unvan', get_unvan(current_user_details['isim']))}"
            if not current_user_details.get("isim_teyit_edildi"):
                current_user_display_name = f"{original_user_profile['isim']} {original_user_profile.get('unvan', get_unvan(original_user_profile['isim']))}"
            user_input_text_this_turn = input(f"{datetime.now().strftime('%H:%M:%S')} 🗣️  {current_user_display_name}: ").strip()
            user_input_text = user_input_text_this_turn
            user_input_text_to_use_in_prompt = user_input_text_this_turn
            if user_input_text.lower() == 'çıkış' or not user_input_text_this_turn :
                print("\n👋 Kullanıcı çıkış yaptı veya boş giriş yaptı.")
                konusma_gecmisi_log_tamami += f"\nUser ({current_user_display_name}): {user_input_text_this_turn if user_input_text_this_turn else '[BOŞ GİRDİ/ÇIKIŞ]'}"
                current_orchestrator_state = "GORUSMEYI_BITIR"
                break
            konusma_gecmisi_log_tamami += f"\nUser ({current_user_display_name}): {user_input_text_this_turn}"
            gecmis_mesajlar_list_llm_icin.append({"role": "user", "content": user_input_text_this_turn})
            short_history_for_intent = format_structured_history(gecmis_mesajlar_list_llm_icin[-6:], turns=3)
            intent_entity_result = await get_intent_and_entities(user_input_text_this_turn, short_history_for_intent, fuzzy_matching_model_library_list)
            detected_intent = intent_entity_result.get("intent", "BELIRSIZ_ALAKASIZ")
            raw_entities = intent_entity_result.get("entities")
            if isinstance(raw_entities, dict):
                detected_entities = {
                    "modeller": raw_entities.get("modeller", []), "markalar": raw_entities.get("markalar", []),
                    "tipler": raw_entities.get("tipler", []), "isim_soyisim": raw_entities.get("isim_soyisim"),
                    "onay_durumu": raw_entities.get("onay_durumu")}
            else:
                 detected_entities = {"modeller": [], "markalar": [], "tipler": [], "isim_soyisim": None, "onay_durumu": None}
                 if DEBUG_MODE: print(f"⚠️ NLU'dan gelen 'entities' alanı bir sözlük değil: {raw_entities}")
            if "error" in intent_entity_result and DEBUG_MODE:
                 print(f"❌ Niyet/Varlık Agent Hatası: {intent_entity_result.get('error')}")

        ai_message_text = "Üzgünüm, bir karışıklık oldu. Ne demek istediğinizi tam anlayamadım."
        next_turn_orchestrator_state_suggestion = current_orchestrator_state
        agent_response_data = None

        prompt_format_values = {
            "MUSTERI_ADI_SOYADI_UNVAN": f"{current_user_details['isim']} {current_user_details.get('unvan', get_unvan(current_user_details['isim']))}",
            "ORIJINAL_PROFIL_BILGISI": f"İsim: {original_user_profile['isim']} {original_user_profile['soyisim']}, Araç: {original_user_profile.get('marka','')} {original_user_profile.get('model','')}",
            "ORIGINAL_PROFILE_ISIM": original_user_profile['isim'],
            "KULLANICI_MESAJI": user_input_text_to_use_in_prompt,
            "NIYET_AGENT_CIKTISI": intent_entity_result,
            "ONCEKI_AI_SORU_TIPI": ai_last_question_type,
            "ISIM_TEYIT_EDILDI_MI": current_user_details.get("isim_teyit_edildi", False),
            "REDDEDILEN_MODELLER": str(list(set(str(m).lower() for m in session_rejected_models))),
            "KONUSMA_GECMISI_FALLBACK": format_structured_history(gecmis_mesajlar_list_llm_icin[-6:], turns=3),
            "DETECTED_INTENT": detected_intent,
            "PYTHON_PROVIDED_ALTERNATIVES_TEXT": "İlgili bir alternatif metni bulunamadı.",
            "ONCEKI_TUR_MODELLERI": str(session_last_offered_models) if session_last_offered_models else "Belirli bir model konuşulmadı.",
            "RECENTLY_UNAVAILABLE_MODELS_CONTEXT": "Yakın zamanda bulunamayan model bilgisi yok.",
            "RECENTLY_UNAVAILABLE_MODELS_AI_EXPLANATION": "Daha önce yapılmış bir AI açıklaması yok.",
            "KULLANICININ_SORDUGU_MODELLER_VE_TIPLER": str(detected_entities.get("modeller", []) + detected_entities.get("tipler", [])),
            "CALISILAN_MARKALAR_STR": "birçok popüler marka"
        }
        recently_unavailable_info = current_user_details.get('recently_unavailable_direct_query_info')
        if recently_unavailable_info:
            prompt_format_values["RECENTLY_UNAVAILABLE_MODELS_CONTEXT"] = f"Kullanıcı daha önce '{recently_unavailable_info['model']}' modelini sordu ve AI'dan '{recently_unavailable_info['ai_explanation']}' şeklinde bir yanıt almıştı."
            prompt_format_values["RECENTLY_UNAVAILABLE_MODELS_AI_EXPLANATION"] = f"Kullanıcı '{recently_unavailable_info['model']}' sorduğunda AI şu yanıtı vermişti: '{recently_unavailable_info['ai_explanation']}'"
        if not isinstance(prompt_format_values["NIYET_AGENT_CIKTISI"].get("entities"), dict):
            if DEBUG_MODE: print(f"⚠️ Niyet Agent Çıktısı 'entities' alanı dict değil, düzeltiliyor (orkestratörde). Çıktı: {prompt_format_values['NIYET_AGENT_CIKTISI']}")
            prompt_format_values["NIYET_AGENT_CIKTISI"]["entities"] = {"modeller": [], "markalar": [], "tipler": [], "isim_soyisim": None, "onay_durumu": None}

        # ==============================================================================
        # ORCHESTRATOR LOGIC - ROUTING TO TASK AGENTS
        # ==============================================================================
        # *** YENİ: TEKLIF_YANITI_BEKLENIYOR durumunda kullanıcı yeni soru sorarsa önceliklendir ***
        if current_orchestrator_state == "TEKLIF_YANITI_BEKLENIYOR":
            question_intents = ["ARAC_SORGU_YENI", "ARAC_SORGU_DETAY_FIYAT",
                                "GENEL_ONERI_ISTEGI", "KULLANICI_TUTARSIZLIK_ALGILADI",
                                "CALISTIGINIZ_MARKALARI_SORMA", "ANLAMADIM_TEKRAR_ISTEGI"]
            is_new_query_or_issue = detected_intent in question_intents
            # NLU'nun onay_durumu: null döndürmesi kritik. True ise, kullanıcı teklifi onaylıyor demektir.
            nlu_indicates_not_confirmed_or_new_query = intent_entity_result.get("entities", {}).get("onay_durumu") is not True

            if is_new_query_or_issue and nlu_indicates_not_confirmed_or_new_query:
                if DEBUG_MODE:
                    print(f"ℹ️ TEKLIF_YANITI_BEKLENIYOR durumunda kullanıcı yeni bir soru/durum belirtti ({detected_intent}).")
                    print(f"    Önceki teklif ({session_last_offered_models}) zımnen reddedilmiş sayılıyor.")
                if session_last_offered_models:
                    for m_rej_text in session_last_offered_models:
                        models_to_reject_from_item = [m.strip().lower() for m in str(m_rej_text).split(',') if m.strip()]
                        for m_lower in models_to_reject_from_item:
                            if m_lower and m_lower not in session_rejected_models:
                                session_rejected_models.append(m_lower)
                                if DEBUG_MODE: print(f"🚫 Model ('{m_lower}') TEKLIF_YANITI_BEKLENIYOR'da yeni soru üzerine reddedilenlere eklendi.")
                    session_last_offered_models = []
                _intent_for_next_turn = detected_intent
                _entities_for_next_turn = detected_entities
                _user_input_for_next_turn_context = user_input_text_to_use_in_prompt
                next_direct_state = "ARAC_ISLEME"
                if detected_intent in ["ARAC_SORGU_YENI", "ARAC_SORGU_DETAY_FIYAT"]: next_direct_state = "ARAC_ISLEME_DIREKT_SORGULA"
                elif detected_intent == "GENEL_ONERI_ISTEGI": next_direct_state = "GENEL_ONERI_ISTEGI_DIREKT_SUN"
                agent_response_data = {"kullanici_yaniti_metni": None, "sonraki_python_durumu_onerisi": next_direct_state,
                                       "ai_sordu_soru_tipi": "SORU_YOK", "agent_name_key_executed": "ORCHESTRATOR_IMPLICIT_REJECTION_HANDLER"}
            else: # Kullanıcı doğrudan teklife yanıt veriyor
                pending_alts_for_models = current_user_details.get('pending_models_for_alternatives', [])
                if ai_last_question_type == "ALTERNATIF_SUNMA_ONAY_SORUSU" and detected_intent == "TEKLIFI_ONAYLAMA" and \
                   pending_alts_for_models and intent_entity_result.get("entities",{}).get("onay_durumu") == True:
                    if DEBUG_MODE: print(f"👍 Kullanıcı '{','.join(pending_alts_for_models)}' için alternatifleri onayladı...")
                    alternatives_found_parts = []; unique_alternatives_suggested = set()
                    for model_orig_lower in pending_alts_for_models:
                        alt_result = suggest_vehicle_alternative(model_orig_lower, df_vehicles)
                        if alt_result and alt_result.get("öneri") and alt_result.get("öneri") not in unique_alternatives_suggested:
                            alternatives_found_parts.append(f"{str(model_orig_lower).capitalize()} yerine {str(alt_result.get('öneri')).capitalize()}")
                            unique_alternatives_suggested.add(alt_result.get("öneri").lower())
                    prompt_format_values["PYTHON_PROVIDED_ALTERNATIVES_TEXT"] = f"Elbette. {', '.join(alternatives_found_parts)} modellerini önerebilirim." if alternatives_found_parts else "Peki, sizin için alternatif modellere baktım ancak şu anda spesifik bir öneri oluşturamadım."
                agent_response_data = await execute_task_agent("OFFER_RESPONSE_HANDLER_AGENT", prompt_format_values)
                current_user_details['pending_models_for_alternatives'] = []
                if DEBUG_MODE: print(f"ℹ️ Bekleyen alternatif sorgusu temizlendi (OFFER_RESPONSE_HANDLER çağrısı sonrası).")
        elif detected_intent == "NEREDEN_ARADINIZ_SORUSU":
            company_intro = f"Ben {COMPANY_NAME}'dan arıyorum."
            q_type_for_next = "KIMLIK_TEYIT_SORUSU"; state_for_next = "KIMLIK_DOGRULAMA_BASLANGIC"
            msg_text_for_who_are_you = f"{company_intro} {original_user_profile['isim']} {get_unvan(original_user_profile['isim'])} ile mi görüşüyorum?" if not current_user_details.get("isim_teyit_edildi") else f"{company_intro}, {current_user_details['isim']} {get_unvan(current_user_details['isim'])}. Size nasıl yardımcı olabilirim?"
            if current_user_details.get("isim_teyit_edildi"): q_type_for_next = "GENEL_YARDIM_SORUSU"; state_for_next = "ARAC_ISLEME"
            agent_response_data = {"kullanici_yaniti_metni": msg_text_for_who_are_you, "sonraki_python_durumu_onerisi": state_for_next, "ai_sordu_soru_tipi": q_type_for_next, "agent_name_key_executed": "INTERNAL_WHO_ARE_YOU_HANDLER"}
        elif current_orchestrator_state == "KIMLIK_DOGRULAMA_BASLANGIC" or \
             (not current_user_details.get("isim_teyit_edildi") and \
              detected_intent in ["KIMLIK_ONAYLAMA", "KIMLIK_DUZELTME_ISIM_VERME", "KIMLIK_REDDETME_GENEL"]):
            # *** DEĞİŞİKLİK: PROFIL_ARACI_ANALIZI için kullanıcı dostu metin ***
            profil_araci_user_friendly_str = ""
            if original_user_profile.get('marka') and original_user_profile.get('model'):
                _profil_araci_tam = f"{original_user_profile.get('marka')} {original_user_profile.get('model')}".lower().strip()
                if _profil_araci_tam and _profil_araci_tam != 'none':
                    sonuc_profil_araci = suggest_vehicle_alternative(_profil_araci_tam, df_vehicles)
                    if sonuc_profil_araci and sonuc_profil_araci.get('öneri'):
                        if sonuc_profil_araci.get('durum') == 1: # Çeviri -> Eşdeğer
                            profil_araci_user_friendly_str = f"Aradığınız '{str(sonuc_profil_araci.get('bulunan')).capitalize()}' modeline ({str(sonuc_profil_araci.get('bulunan')).capitalize()} olarak kayıtlı) alternatif olarak '{str(sonuc_profil_araci.get('öneri')).capitalize()}' modelini önerebiliriz."
                        elif sonuc_profil_araci.get('durum') == 2: # Doğrudan mevcut
                             profil_araci_user_friendly_str = f"Evet, '{str(sonuc_profil_araci.get('öneri')).capitalize()}' modelimiz mevcut." # Profil aracı = öneri
                        elif sonuc_profil_araci.get('durum') == 3: # Alternatif öneri
                            profil_araci_user_friendly_str = f"Aradığınız '{str(sonuc_profil_araci.get('bulunan')).capitalize()}' modeli için size alternatif olarak '{str(sonuc_profil_araci.get('öneri')).capitalize()}' modelini önerebiliriz."
                        elif sonuc_profil_araci.get('durum') == 4: # Bulunamadı
                             profil_araci_user_friendly_str = f"Aradığınız '{str(sonuc_profil_araci.get('bulunan')).capitalize()}' modeli için şu anda uygun bir alternatifimiz bulunmuyor."
            prompt_format_values["PROFIL_ARACI_ANALIZI"] = profil_araci_user_friendly_str if profil_araci_user_friendly_str else "" # Boş yolla ki agent ona göre davransın
            # *** DEĞİŞİKLİK SONU ***
            agent_response_data = await execute_task_agent("IDENTITY_HANDLER_AGENT", prompt_format_values)
            if agent_response_data and "error" not in agent_response_data:
                agent_karari = agent_response_data.get("agent_karari"); g_isim_soyisim = agent_response_data.get("guncellenmis_isim_soyisim")
                if agent_karari == "ONAYLANDI":
                    current_user_details.update(original_user_profile); current_user_details["isim_teyit_edildi"] = True
                    if DEBUG_MODE: print(f"📝 Kimlik ONAYLANDI ({current_user_details['isim']}).")
                elif agent_karari in ["DUZELTILDI_FARKLI_KISI", "YENI_KISI_TANIMLANDI"]:
                    if g_isim_soyisim:
                        parts = str(g_isim_soyisim).split(" ", 1); current_user_details['isim'] = parts[0].capitalize(); current_user_details['soyisim'] = parts[1].capitalize() if len(parts) > 1 else ""; current_user_details['unvan'] = get_unvan(current_user_details['isim']); current_user_details["isim_teyit_edildi"] = True
                        current_user_details['marka'] = None; current_user_details['model'] = None
                        if DEBUG_MODE: print(f"📝 Kimlik YENİ KİŞİ/DÜZELTİLDİ: {current_user_details['isim']} {current_user_details['soyisim']}.")
        elif current_user_details.get("isim_teyit_edildi"):
            if detected_intent in ["ARAC_SORGU_YENI", "ARAC_SORGU_DETAY_FIYAT"]:
                python_arac_analizi_str_lines = [];
                sordugu_modeller_ve_tipler_entity = detected_entities.get("modeller", []) + detected_entities.get("tipler", [])
                if not sordugu_modeller_ve_tipler_entity and user_input_text_this_turn:
                    sordugu_modeller_ve_tipler_entity = find_models_in_text_from_library(user_input_text_this_turn, fuzzy_matching_model_library_list)
                processed_items_for_agent = set()
                current_user_details['recently_unavailable_direct_query_info'] = None
                for item_s in sordugu_modeller_ve_tipler_entity:
                    item_s_lower = str(item_s).lower().strip()
                    if not item_s_lower or item_s_lower in processed_items_for_agent: continue
                    processed_items_for_agent.add(item_s_lower)
                    if item_s_lower not in ["elektrikli", "dizel", "benzinli", "suv", "sedan", "hatchback", "otomatik", "manuel"]:
                        sonuc = suggest_vehicle_alternative(item_s_lower, df_vehicles)
                        python_arac_analizi_str_lines.append(f"- Talep Edilen '{str(sonuc.get('bulunan')).capitalize()}': Durum {sonuc.get('durum')}, Öneri: {str(sonuc.get('öneri')).capitalize() if sonuc.get('öneri') else 'Yok'}, Excelde Var: {sonuc.get('excelde_var')}, Açıklama: {sonuc.get('mesaj')}")
                        if sonuc.get('durum') in [3, 4]: current_user_details['recently_unavailable_direct_query_info'] = {"model": item_s_lower, "ai_explanation": sonuc.get('mesaj')}
                    else: python_arac_analizi_str_lines.append(f"- Talep Edilen Araç Tipi/Özelliği: '{item_s_lower.capitalize()}'.")
                prompt_format_values["PYTHON_ARAC_ANALIZ_SONUCLARI"] = "\n".join(python_arac_analizi_str_lines) if python_arac_analizi_str_lines else "- Kullanıcının sorguladığı modeller/tipler için özel Python analizi bulunamadı veya bir model/tip belirtilmedi."
                prompt_format_values["KULLANICININ_SORDUGU_MODELLER_VE_TIPLER"] = str(list(processed_items_for_agent)) if processed_items_for_agent else "Belirtilmedi"
                agent_response_data = await execute_task_agent("VEHICLE_INQUIRY_AGENT", prompt_format_values)
                if agent_response_data and not agent_response_data.get("error"):
                    if agent_response_data.get("ai_sordu_soru_tipi") == "ALTERNATIF_SUNMA_ONAY_SORUSU": # VEHICLE_INQUIRY_AGENT bunu artık sormuyor, direkt ARAC_ILGI_SORUSU soruyor.
                        unavailable_from_agent_list = agent_response_data.get("unavailable_models_queried", [])
                        if unavailable_from_agent_list: current_user_details['pending_models_for_alternatives'] = [m.lower() for m in unavailable_from_agent_list]
                    elif current_user_details['pending_models_for_alternatives']: current_user_details['pending_models_for_alternatives'] = []
            elif detected_intent == "GENEL_ONERI_ISTEGI":
                all_possible_suggestions = []
                for col_suggest in ['eş değeri', 'elektrikli', 'öneri3', 'öneri4', 'öneri5']:
                    if col_suggest in df_vehicles.columns:
                        models_in_col_suggest = df_vehicles[col_suggest].dropna().astype(str).str.lower().str.strip().unique()
                        all_possible_suggestions.extend([m for m in models_in_col_suggest if m and m != 'none'])
                valid_suggestions = [m.capitalize() for m in sorted(list(set(all_possible_suggestions))) if m not in session_rejected_models]
                öneri_listesi_str = ("Mevcut modellerimizden bazıları: " + ", ".join(random.sample(valid_suggestions, min(len(valid_suggestions), 3)))) if valid_suggestions else "Şu an için size özel bir öneri listesi hazırlayamadım."
                prompt_format_values["PYTHON_GENEL_ONERI_LISTESI"] = öneri_listesi_str
                prompt_format_values["KONUSULAN_REDDEDILEN_MODELLER"] = f"Daha önce konuşulanlar (son mesajlar): {format_structured_history(gecmis_mesajlar_list_llm_icin[-5:], turns=2)}\nReddedilenler: {str(session_rejected_models)}"
                agent_response_data = await execute_task_agent("GENERAL_RECOMMENDATION_AGENT", prompt_format_values)
                current_user_details['recently_unavailable_direct_query_info'] = None
            elif detected_intent == "CALISTIGINIZ_MARKALARI_SORMA":
                # available_brands_list = get_unique_brands_from_models(df_vehicles) # Aktif edilecek
                # prompt_format_values["CALISILAN_MARKALAR_STR"] = ", ".join(available_brands_list) if available_brands_list else "birçok popüler marka"
                agent_response_data = await execute_task_agent("FALLBACK_AGENT", prompt_format_values)
            elif detected_intent == "VEDALASMA_KAPATMA":
                agent_response_data = await execute_task_agent("FAREWELL_AGENT", prompt_format_values)
            elif detected_intent in ["ANLAMADIM_TEKRAR_ISTEGI", "KULLANICI_TUTARSIZLIK_ALGILADI", "BELIRSIZ_ALAKASIZ"]:
                if DEBUG_MODE: print(f"DEFANSİF (kimlik sonrası): Niyet '{detected_intent}' Fallback Agent'a yönlendiriliyor.")
                agent_response_data = await execute_task_agent("FALLBACK_AGENT", prompt_format_values)
            else:
                if DEBUG_MODE: print(f"DEFANSİF (kimlik sonrası, BEKLENMEDİK DURUM): Niyet '{detected_intent}' için hiçbir işleyici bulunamadı, Fallback Agent'a yönlendiriliyor.")
                agent_response_data = await execute_task_agent("FALLBACK_AGENT", prompt_format_values)
        else:
            if DEBUG_MODE: print(f"DEFANSİF (kimlik öncesi): Niyet '{detected_intent}' kimlik işlemleriyle ilgili değil ({current_orchestrator_state}), Fallback Agent'a yönlendiriliyor.")
            agent_response_data = await execute_task_agent("FALLBACK_AGENT", prompt_format_values)

        # ==============================================================================
        # AGENT RESPONSE PROCESSING & STATE UPDATE
        # ==============================================================================
        if agent_response_data and "error" not in agent_response_data:
            ai_message_text = agent_response_data.get("kullanici_yaniti_metni")
            next_turn_orchestrator_state_suggestion = agent_response_data.get("sonraki_python_durumu_onerisi", current_orchestrator_state)
            ai_last_question_type = agent_response_data.get("ai_sordu_soru_tipi", "SORU_YOK")

            # *** YENİ: _intent_for_next_turn ayarını OFFER_RESPONSE_HANDLER veya ORCHESTRATOR_IMPLICIT_REJECTION_HANDLER'dan gelen verilere göre yap ***
            executed_agent_for_direct_action = agent_response_data.get('agent_name_key_executed')
            if executed_agent_for_direct_action in ["OFFER_RESPONSE_HANDLER_AGENT", "ORCHESTRATOR_IMPLICIT_REJECTION_HANDLER"] and ai_message_text is None:
                if agent_response_data.get("kullanicinin_yeni_sordugu_modeller") and \
                   next_turn_orchestrator_state_suggestion == "ARAC_ISLEME_DIREKT_SORGULA":
                    _intent_for_next_turn = "ARAC_SORGU_YENI"
                    _entities_for_next_turn = {"modeller": [m.lower().strip() for m in agent_response_data["kullanicinin_yeni_sordugu_modeller"]], "markalar": [], "tipler": [], "isim_soyisim": None, "onay_durumu": None}
                    _user_input_for_next_turn_context = user_input_text
                    if DEBUG_MODE: print(f"    Sonraki tur için ayarlandı (YENİ SORGULAMA): _intent='{_intent_for_next_turn}'")
                elif next_turn_orchestrator_state_suggestion == "GENEL_ONERI_ISTEGI_DIREKT_SUN":
                    _intent_for_next_turn = "GENEL_ONERI_ISTEGI"
                    _entities_for_next_turn = {"modeller": [], "markalar": [], "tipler": [], "isim_soyisim": None, "onay_durumu": None}
                    _user_input_for_next_turn_context = user_input_text
                    if DEBUG_MODE: print(f"    Sonraki tur için ayarlandı (GENEL ÖNERİ): _intent='{_intent_for_next_turn}'")
            # *** YENİ SONU ***

            offered_this_turn_raw = agent_response_data.get("onerilen_modeller_yanitta") or agent_response_data.get("onerilen_veya_teyit_edilen_modeller_yanitta")
            if offered_this_turn_raw and isinstance(offered_this_turn_raw, list):
                session_last_offered_models = [str(m).lower().strip() for m in offered_this_turn_raw if str(m).strip()]
                if DEBUG_MODE: print(f"ℹ️ Sonraki tur için konuşulan/önerilen modeller güncellendi: {session_last_offered_models}")
            elif ai_last_question_type not in ["ARAC_ILGI_SORUSU", "BAYI_ONAY_SORUSU", "ALTERNATIF_SUNMA_ONAY_SORUSU", "ARAC_TIP_SORUSU", "BAYI_MODEL_TEYIT_SORUSU"]:
                if session_last_offered_models:
                    if DEBUG_MODE: print(f"ℹ️ Belirli bir model teklifi/konuşması yapılmadığı için session_last_offered_models temizlendi. Soru Tipi: {ai_last_question_type}")
                    session_last_offered_models = []
            rejected_in_turn_raw = agent_response_data.get("reddedilen_modeller_bu_tur", [])
            if rejected_in_turn_raw and isinstance(rejected_in_turn_raw, list):
                newly_rejected_processed = []
                for item_rej in rejected_in_turn_raw:
                    models_from_item = [m.strip().lower() for m in str(item_rej).split(',') if m.strip()]
                    newly_rejected_processed.extend(models_from_item)
                for m_lower in newly_rejected_processed:
                    if m_lower and m_lower not in session_rejected_models:
                        session_rejected_models.append(m_lower)
                        if DEBUG_MODE: print(f"🚫 Model reddedilenlere eklendi (Agent: {agent_response_data.get('agent_name_key_executed')}): {m_lower}")

            current_orchestrator_state = next_turn_orchestrator_state_suggestion

            if ai_message_text is None and _intent_for_next_turn and \
               current_orchestrator_state in ["ARAC_ISLEME_DIREKT_SORGULA", "GENEL_ONERI_ISTEGI_DIREKT_SUN"]:
                if ai_last_question_type == "SORU_YOK" and current_orchestrator_state != "GORUSMEYI_BITIR":
                    if DEBUG_MODE: print(f"    AI mesajı boş & SORU_YOK & sonraki niyet var. Durum '{current_orchestrator_state}'. Direkt devam ediliyor.")
                    continue
            if ai_last_question_type in ["BAYI_ONAY_SORUSU", "ARAC_ILGI_SORUSU", "ALTERNATIF_SUNMA_ONAY_SORUSU", "BAYI_MODEL_TEYIT_SORUSU"]:
                current_orchestrator_state = "TEKLIF_YANITI_BEKLENIYOR"
            elif ai_last_question_type in ["KIMLIK_TEYIT_SORUSU", "KIMLIK_ISIM_SORUSU"]:
                current_orchestrator_state = "KIMLIK_DOGRULAMA_BASLANGIC"
            elif current_orchestrator_state not in ["ARAC_ISLEME_DIREKT_SORGULA", "GENEL_ONERI_ISTEGI_DIREKT_SUN", "GORUSMEYI_BITIR", "TEKLIF_YANITI_BEKLENIYOR", "KIMLIK_DOGRULAMA_BASLANGIC"]:
                 if current_user_details.get("isim_teyit_edildi"): current_orchestrator_state = "ARAC_ISLEME"
                 else: current_orchestrator_state = "KIMLIK_DOGRULAMA_BASLANGIC"
        elif agent_response_data and "error" in agent_response_data:
            ai_message_text = f"Üzgünüm, bir sorunla karşılaştık ({agent_response_data.get('error', 'bilinmeyen hata')}). Lütfen farklı bir şekilde ifade eder misiniz?"
            ai_last_question_type = "GENEL_YARDIM_SORUSU"
            if DEBUG_MODE: print(f"❌ Agent ({agent_response_data.get('agent_name_key_executed')}) Hatası: {agent_response_data.get('error')}")
            if current_user_details.get("isim_teyit_edildi"): current_orchestrator_state = "ARAC_ISLEME"
            else: current_orchestrator_state = "KIMLIK_DOGRULAMA_BASLANGIC"
        else:
             ai_message_text = "Sistemde bir sorun oluştu, özür dileriz. Lütfen daha sonra tekrar deneyin."
             if DEBUG_MODE: print(f"❌ Agent_response_data alınamadı veya beklenmedik bir hata oluştu.")
             current_orchestrator_state = "GORUSMEYI_BITIR"

        if ai_message_text is not None:
            print(f"{datetime.now().strftime('%H:%M:%S')} 🧠 AI: {ai_message_text}")
            konusma_gecmisi_log_tamami += f"\nAI: {ai_message_text}"
            gecmis_mesajlar_list_llm_icin.append({"role": "assistant", "content": ai_message_text})
        elif current_orchestrator_state not in ["ARAC_ISLEME_DIREKT_SORGULA", "GENEL_ONERI_ISTEGI_DIREKT_SUN", "GORUSMEYI_BITIR"] and DEBUG_MODE :
            print(f"⚠️ AI Mesajı Boş Geldi (None) ancak direkt devam durumu değil. Durum: {current_orchestrator_state}, Son Soru: {ai_last_question_type}")

        if current_orchestrator_state == "GORUSMEYI_BITIR":
            if DEBUG_MODE: print(f"🏁 Orkestratör durumu GORUSMEYI_BITIR. Döngü sonlandırılıyor.")
            break
        if len(gecmis_mesajlar_list_llm_icin) > 20:
            if DEBUG_MODE: print("Konuşma geçmişi son 10 turu içerecek şekilde kısaltılıyor.")
            gecmis_mesajlar_list_llm_icin = gecmis_mesajlar_list_llm_icin[-20:]

    print("\n🏁 Görüşme döngüsü tamamlandı. Son analiz ve kayıt işlemleri yapılıyor...")
    await analiz_et_ve_kaydet_veritabani_async(
        konusma_gecmisi_str=konusma_gecmisi_log_tamami,
        user_id=original_user_profile["id"],
        user_final_details=current_user_details)
    print("İşlemler tamamlandı.")

if __name__ == "__main__":
    if not OPENROUTER_API_KEY:
        print("HATA: OPENROUTER_API_KEY .env dosyasında bulunamadı veya yüklenemedi. Program çalıştırılamıyor.")
    else:
        try:
            asyncio.run(main_async_llm_driven())
        except KeyboardInterrupt:
            print("\nProgram kullanıcı tarafından sonlandırıldı (KeyboardInterrupt).")
        except EOFError:
            print("\nVeri girişi beklenmedik bir şekilde sonlandı (EOFError).")
        finally:
            print("Asenkron program sonlandı.")