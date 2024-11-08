import aes128
import argparse
import key_sources as key_sources

argParser = argparse.ArgumentParser()
argParser.add_argument("-k", "--keys", help="Where you want the keys to be saved")
args = argParser.parse_args()
prod_keys = "%s" % args.keys


if prod_keys == "None":
    keys = "dev.keys"
else: 
    keys = prod_keys

def decrypt(key, decryption_key):
	crypto = aes128.AESECB(decryption_key)
	return crypto.decrypt(key)

def generateKek(src, masterKey, kek_seed, key_seed):
	kek = []
	src_kek = []

	crypto = aes128.AESECB(masterKey)
	kek = crypto.decrypt(kek_seed)

	crypto = aes128.AESECB(kek)
	src_kek = crypto.decrypt(src)

	if key_seed is not None:
		crypto = aes128.AESECB(src_kek)
		return crypto.decrypt(key_seed)
	else:
		return src_kek

with open(keys, 'w') as manual_crypto:	
	manual_crypto.write(f'tsec_auth_signature_00 = ' + f'{key_sources.tsec_auth_signature_00.hex().upper()}\n')
	manual_crypto.write(f'tsec_auth_signature_01 = ' + f'{key_sources.tsec_auth_signature_00.hex().upper()}\n')
	manual_crypto.write(f'tsec_auth_signature_02 = ' + f'{key_sources.tsec_auth_signature_00.hex().upper()}\n\n')

	manual_crypto.write(f'tsec_root_key_02 = ' + f'{key_sources.tsec_root_key_02_dev.hex().upper()}\n\n')

	manual_crypto.write(f'keyblob_mac_key_source = ' + f'{key_sources.keyblob_mac_key_source.hex().upper()}\n')
	# Write keyblob_key_source_%%
	count = -1
	for i in key_sources.Keyblob_Key_Sources:
		count = count + 0x1
		keys = f'keyblob_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')
	# Write master_kek_sources
	count = 0x5
	for i in key_sources.master_kek_sources:
		count = count + 0x1
		keys = f'master_kek_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')

	# Write mariko_master_kek_sources
	count = 0x4
	for i in key_sources.mariko_master_kek_sources:
		count = count + 0x1
		keys = f'mariko_master_kek_source_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')
	# generate master_kek_%% from all provided mariko_master_kek_sources
	master_keks = [decrypt(i, key_sources.tsec_root_key_02_dev) for i in key_sources.master_kek_sources]
	count = 0x5
	for i in master_keks:
		count = count + 0x1
		keys = f'master_kek_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')
	
	manual_crypto.write(f'\n')
	manual_crypto.write(f'master_key_source = ' + f'{key_sources.master_key_source.hex().upper()}\n\n')

	# generate master_key_%% from all provided master_kek_%% using master_key_source
	current_master_key = decrypt(key_sources.master_key_source, master_keks[-1])

	current_master_key_revision = len(key_sources.Master_Key_Sources_Dev)
	master_keys = []
	first = True
	for i in reversed(key_sources.Master_Key_Sources_Dev):
		if first:
			first = False
			previous_key = i
			next_master_key = decrypt(previous_key, current_master_key)
			current_master_key_revision = current_master_key_revision -1
			master_keys.append(current_master_key)
			master_keys.append(next_master_key)
		else:
			key = previous_key
			previous_key = i
			next_master_key = decrypt(previous_key, next_master_key)
			current_master_key_revision = current_master_key_revision -1
			master_keys.append(next_master_key)


	# Write master_key_%%
	count = -0x1
	for i in reversed(master_keys):
		count = count + 0x1
		keys = f'master_key_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')
	manual_crypto.write(f'package2_key_source = ' + f'{key_sources.package2_key_source.hex().upper()}\n\n')

	# generate package2_key_%% from all provided master_key_%% using package2_key_source
	package2_key = [decrypt(key_sources.package2_key_source, i) for i in master_keys]
	count = -0x1
	for i in package2_key:
		count = count + 0x1
		keys = f'package2_key_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')
	manual_crypto.write(f'bis_kek_source = ' + f'{key_sources.bis_kek_source.hex().upper()}\n')
	# Write bis_key_source_%%
	count = -1
	for i in key_sources.Bis_Key_Sources:
		count = count + 0x1
		keys = f'bis_key_source_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')
	manual_crypto.write(f'per_console_key_source = ' + f'{key_sources.per_console_key_source.hex().upper()}\n')
	manual_crypto.write(f'retail_specific_aes_key_source = ' + f'{key_sources.retail_specific_aes_key_source.hex().upper()}\n')
	manual_crypto.write(f'aes_kek_generation_source = ' + f'{key_sources.aes_kek_generation_source.hex().upper()}\n')
	manual_crypto.write(f'aes_key_generation_source = ' + f'{key_sources.aes_key_generation_source.hex().upper()}\n')
	manual_crypto.write(f'titlekek_source = ' + f'{key_sources.titlekek_source.hex().upper()}\n\n')

	# generate title_kek_%% from all provided master_key_%% using titlekek_source
	titlekek = [decrypt(key_sources.titlekek_source, i) for i in master_keys]
	count = -0x1
	for i in titlekek:
		count = count + 0x1
		keys = f'titlekek_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')

	manual_crypto.write(f'header_kek_source = ' + f'{key_sources.header_kek_source.hex().upper()}\n')
	manual_crypto.write(f'header_key_source = ' + f'{key_sources.header_key_source.hex().upper()}\n')
	manual_crypto.write(f'header_key = ' + f'{key_sources.header_key.hex().upper()}\n\n')

	manual_crypto.write(f'key_area_key_system_source = ' + f'{key_sources.key_area_key_system_source.hex().upper()}\n')
	manual_crypto.write(f'key_area_key_application_source = ' + f'{key_sources.key_area_key_application_source.hex().upper()}\n')
	manual_crypto.write(f'key_area_key_ocean_source = ' + f'{key_sources.key_area_key_ocean_source.hex().upper()}\n\n')

	manual_crypto.write(f'save_mac_kek_source = ' + f'{key_sources.save_mac_kek_source.hex().upper()}\n')
	manual_crypto.write(f'save_mac_key_source_00 = ' + f'{key_sources.save_mac_key_source_00.hex().upper()}\n')
	manual_crypto.write(f'save_mac_key_source_01 = ' + f'{key_sources.save_mac_key_source_01.hex().upper()}\n')
	manual_crypto.write(f'save_mac_sd_card_kek_source = ' + f'{key_sources.save_mac_sd_card_kek_source.hex().upper()}\n')
	manual_crypto.write(f'save_mac_sd_card_key_source = ' + f'{key_sources.save_mac_sd_card_key_source.hex().upper()}\n')
	manual_crypto.write(f'sd_card_kek_source = ' + f'{key_sources.sd_card_kek_source.hex().upper()}\n\n')


	# generate key_area_key_application_%% from all provided master_key_%% using key_area_key_application_source
	key_area_key_application = [generateKek(key_sources.key_area_key_application_source, i, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source) for i in master_keys]
	count = -0x1
	for i in key_area_key_application:
		count = count +0x1
		keys = f'key_area_key_application_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')

	# generate key_area_key_ocean_%% from all provided master_key_%% using key_area_key_ocean_source
	key_area_key_ocean = [generateKek(key_sources.key_area_key_ocean_source, i, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source) for i in master_keys]
	count = -0x1
	for i in key_area_key_ocean:
		count = count +0x1
		keys = f'key_area_key_ocean_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')

	manual_crypto.write(f'\n')

	# generate key_area_key_system_%% from all provided master_key_%% using key_area_key_system_source
	key_area_key_system = [generateKek(key_sources.key_area_key_system_source, i, key_sources.aes_kek_generation_source, key_sources.aes_key_generation_source) for i in master_keys]
	count = -0x1
	for i in key_area_key_system:
		count = count +0x1
		keys = f'key_area_key_system_dev_{hex(count)[2:].zfill(2)} = '  + (i.hex().upper())
		manual_crypto.write(f'{keys}\n')