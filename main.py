
import asyncio
import json
import time
from indy import pool, wallet, did, ledger, anoncreds, blob_storage
from indy.error import ErrorCode, IndyError
from os.path import dirname


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp=None):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Get Revocation Definitions and Revocation Registries
            print("\"{}\" -> Get Revocation Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry from Ledger".format(actor))
            if not timestamp: timestamp = item['timestamp']
            get_revoc_reg_request = \
                await ledger.build_get_revoc_reg_request(_did, item['rev_reg_id'], timestamp)
            get_revoc_reg_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, rev_reg_json, timestamp2) = await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)

            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ensure_previous_request_applied(
        pool_handle, get_schema_request, lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = \
        await ensure_previous_request_applied(pool_handle, get_cred_def_request,
                                              lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)



async def ensure_previous_request_applied(pool_handle, checker_request, checker):
    for _ in range(3):
        response = json.loads(await ledger.submit_request(pool_handle, checker_request))
        try:
            if checker(response):
                return json.dumps(response)
        except TypeError:
            pass
        time.sleep(5)


async def create_wallet(identity):
    print("\"{}\" -> Create wallet".format(identity['name']))
    try:
        await wallet.create_wallet(identity['wallet_config'],
                                   identity['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    identity['wallet'] = await wallet.open_wallet(identity['wallet_config'],
                                                  identity['wallet_credentials'])



async def getting_verinym(from_, to):
    await create_wallet(to)

    (to['did'], to['key']) = await did.create_and_store_my_did(to['wallet'], "{}")

    from_['info'] = {
        'did': to['did'],
        'verkey': to['key'],
        'role': to['role'] or None
    }

    await send_nym(from_['pool'], from_['wallet'], from_['did'], from_['info']['did'],
                   from_['info']['verkey'], from_['info']['role'])


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    print(nym_request)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp_from=None,
                                          timestamp_to=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.", item['schema_id'])
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Create Revocations States
            print("\"{}\" -> Get Revocation Registry Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry Delta from Ledger".format(actor))
            if not timestamp_to: timestamp_to = int(time.time())
            get_revoc_reg_delta_request = \
                await ledger.build_get_revoc_reg_delta_request(_did, item['rev_reg_id'], timestamp_from, timestamp_to)
            get_revoc_reg_delta_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_delta_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_delta_json, t) = \
                await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)

            tails_reader_config = json.dumps(
                {'base_dir': dirname(json.loads(revoc_reg_def_json)['value']['tailsLocation']),
                 'uri_pattern': ''})
            blob_storage_reader_cfg_handle = await blob_storage.open_reader('default', tails_reader_config)

            print('%s - Create Revocation State', actor)
            rev_state_json = \
                await anoncreds.create_revocation_state(blob_storage_reader_cfg_handle, revoc_reg_def_json,
                                                        revoc_reg_delta_json, t, item['cred_rev_id'])
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def run():

    pool_ = {
        'name': 'pool1'
    }
    print("Open Pool Ledger: {}".format(pool_['name']))
    pool_['genesis_txn_path'] = "pool1.txn"
    pool_['config'] = json.dumps({"genesis_txn": str(pool_['genesis_txn_path'])})

    print(pool_)

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(2)

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print(pool_['handle'])
    #    --------------------------------------------------------------------------
    #  Accessing a steward.

    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }
    print(steward)

    await create_wallet(steward)

    print(steward["wallet"])

    steward["did_info"] = json.dumps({'seed':steward['seed']})
    print(steward["did_info"])

    # did:demoindynetwork:Th7MpTaRZVRYnPiabds81Y
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])


    # ----------------------------------------------------------------------
    # Create and register dids for Government, University and company
    # 
    print("\n\n\n==============================")
    print("==  Government registering Verinym  ==")
    print("------------------------------")


    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, government)



    print("==============================")
    print("== theUniversity getting Verinym  ==")
    print("------------------------------")

    theUniversity = {
        'name': 'theUniversity',
        'wallet_config': json.dumps({'id': 'theUniversity_wallet'}),
        'wallet_credentials': json.dumps({'key': 'theUniversity_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, theUniversity)

    print("==============================")
    print("== theCompany getting Verinym  ==")
    print("------------------------------")

    theCompany = {
        'name': 'theCompany',
        'wallet_config': json.dumps({'id': 'theCompany_wallet'}),
        'wallet_credentials': json.dumps({'key': 'theCompany_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, theCompany)

    # -----------------------------------------------------
    # Government creates transcript schema

    print("\"Government\" -> Create \"Transcript\" Schema")
    transcript = {
        'name': 'Transcript',
        'version': '1.2',
        'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
    }
    (government['transcript_schema_id'], government['transcript_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], transcript['name'], transcript['version'],
                                             json.dumps(transcript['attributes']))
    
    print(government['transcript_schema'])
    transcript_schema_id = government['transcript_schema_id']

    print(government['transcript_schema_id'], government['transcript_schema'])

    print("\"Government\" -> Send \"Transcript\" Schema to Ledger")

    
    schema_request = await ledger.build_schema_request(government['did'], government['transcript_schema'])
    await ledger.sign_and_submit_request(government['pool'], government['wallet'], government['did'], schema_request)
    

    # -----------------------------------------------------
    # University will create a credential definition
    
    print("\n\n==============================")
    print("=== theUniversity Credential Definition Setup ==")
    print("------------------------------")

    print("\"theUniversity\" -> Get \"Transcript\" Schema from Ledger")

    # GET SCHEMA FROM LEDGER
    get_schema_request = await ledger.build_get_schema_request(theUniversity['did'], transcript_schema_id)
    get_schema_response = await ensure_previous_request_applied(
        theUniversity['pool'], get_schema_request, lambda response: response['result']['data'] is not None)
    (theUniversity['transcript_schema_id'], theUniversity['transcript_schema']) = await ledger.parse_get_schema_response(get_schema_response)

    # TRANSCRIPT CREDENTIAL DEFINITION
    print("\"theUniversity\" -> Create and store in Wallet \"theUniversity Transcript\" Credential Definition")
    transcript_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (theUniversity['transcript_cred_def_id'], theUniversity['transcript_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(theUniversity['wallet'], theUniversity['did'],
                                                               theUniversity['transcript_schema'], transcript_cred_def['tag'],
                                                               transcript_cred_def['type'],
                                                               json.dumps(transcript_cred_def['config']))

    print("\"theUniversity\" -> Send  \"theUniversity Transcript\" Credential Definition to Ledger")
    # print(theUniversity['transcript_cred_def'])

    cred_def_request = await ledger.build_cred_def_request(theUniversity['did'], theUniversity['transcript_cred_def'])
    # print(cred_def_request)
    await ledger.sign_and_submit_request(theUniversity['pool'], theUniversity['wallet'], theUniversity['did'], cred_def_request)
    print("\n\n>>>>>>>>>>>>>>>>>>>>>>.\n\n", theUniversity['transcript_cred_def_id'])

    # ------------------------------------------------------------
    #  rahul getting transcript from university

    print("==============================")
    print("=== Getting Transcript with theUniversity ==")
    print("==============================")
    
    print("== rahul setup ==")
    print("------------------------------")

    rahul = {
        'name': 'rahul',
        'wallet_config': json.dumps({'id': 'rahul_wallet'}),
        'wallet_credentials': json.dumps({'key': 'rahul_wallet_key'}),
        'pool': pool_['handle'],
    }
    await create_wallet(rahul)
    (rahul['did'], rahul['key']) = await did.create_and_store_my_did(rahul['wallet'], "{}")

    # University creates transcript credential offer

    print("\"theUniversity\" -> Create \"Transcript\" Credential Offer for rahul")
    theUniversity['transcript_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(theUniversity['wallet'], theUniversity['transcript_cred_def_id'])

    print("\"theUniversity\" -> Send \"Transcript\" Credential Offer to rahul")
    
    # Over Network 
    rahul['transcript_cred_offer'] = theUniversity['transcript_cred_offer']

    print(rahul['transcript_cred_offer'])

    # rahul prepares a transcript credential request

    transcript_cred_offer_object = json.loads(rahul['transcript_cred_offer'])

    rahul['transcript_schema_id'] = transcript_cred_offer_object['schema_id']
    rahul['transcript_cred_def_id'] = transcript_cred_offer_object['cred_def_id']

    print("\"rahul\" -> Create and store \"rahul\" Master Secret in Wallet")
    rahul['master_secret_id'] = await anoncreds.prover_create_master_secret(rahul['wallet'], None)

    print("\"rahul\" -> Get \"theUniversity Transcript\" Credential Definition from Ledger")
    (rahul['theUniversity_transcript_cred_def_id'], rahul['theUniversity_transcript_cred_def']) = \
        await get_cred_def(rahul['pool'], rahul['did'], rahul['transcript_cred_def_id'])

    print("\"rahul\" -> Create \"Transcript\" Credential Request for theUniversity")
    (rahul['transcript_cred_request'], rahul['transcript_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(rahul['wallet'], rahul['did'],
                                                     rahul['transcript_cred_offer'],
                                                     rahul['theUniversity_transcript_cred_def'],
                                                     rahul['master_secret_id'])

    print("\"rahul\" -> Send \"Transcript\" Credential Request to theUniversity")

    # Over Network
    theUniversity['transcript_cred_request'] = rahul['transcript_cred_request']
    
    print("University issues Credential to Rahul")
    theUniversity['rahul_transcript_cred_values'] = json.dumps({
        "first_name": {"raw":"Rahul", "encoded":"11221122112211221122112211221122"},
        "last_name": {"raw":"Kulkarni", "encoded":"909090909090909090909090909090"},
        "degree":{"raw":"Bachelor of Science, Marketing", "encoded":"12345678901234567890"},
        "status": {"raw":"Graduated", "encoded":"12345678900987654321"},
        "ssn": {"raw":"123-45-6789", "encoded":"123123123123123123123123123123"},
        "year": {"raw":"2024", "encoded":"2024"},
        "average":{"raw":"5","encoded":"5"}
    })

    theUniversity['transcript_cred'], _, _ = \
        await anoncreds.issuer_create_credential(theUniversity['wallet'], theUniversity['transcript_cred_offer'],
        theUniversity['transcript_cred_request'],
        theUniversity['rahul_transcript_cred_values'], None, None)

    print(theUniversity['transcript_cred'])

    #over the network
    rahul['transcript_cred'] = theUniversity['transcript_cred']

    print("\"Rahul\" -> Strore \"Transcript\" Credential from theUniversity")
    _, rahul['transcript_cred_def'] = await get_cred_def(rahul['pool'], rahul['did'],
    rahul['transcript_cred_def_id'])

    await anoncreds.prover_store_credential(rahul['wallet'], None, rahul['transcript_cred_request_metadata'], rahul['transcript_cred'], rahul['transcript_cred_def'], None)

    print("\n\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n", rahul['transcript_cred_def'])
     
    # Verifiable Presentation

    # Creating application request (presentaion request) --- validator - theCompany
    print("\"theCompany\" -> Create \"Job-Application\" Proof Request")
    nonce = await anoncreds.generate_nonce()
    theCompany['job_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': theUniversity['transcript_cred_def_id']}]
            }
        }
    })

    print("\"theCompany\" -> Send \"Job-Application\" Proof Request to rahul")

    # Over Network
    rahul['job_application_proof_request'] = theCompany['job_application_proof_request']

    print(rahul['job_application_proof_request'])

    # rahul prepares the presentation ===================================

    print("\n\n>>>>>>>>>>>>>>>>>>>>>>.\n\n", rahul['job_application_proof_request'])

    print("\"rahul\" -> Get credentials for \"Job-Application\" Proof Request")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(rahul['wallet'],
                                                                rahul['job_application_proof_request'], None)
    
    print("---------------------------")
    print(search_for_job_application_proof_request)
    print("---------------------------")

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')
    
    print("---------------------------")
    print(cred_for_attr1)
    print("---------------------------")


    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    rahul['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(rahul['creds_for_job_application_proof'])

    rahul['schemas_for_job_application'], rahul['cred_defs_for_job_application'], \
    rahul['revoc_states_for_job_application'] = \
        await prover_get_entities_from_ledger(rahul['pool'], rahul['did'],
                                              rahul['creds_for_job_application_proof'], rahul['name'])

    print("\"rahul\" -> Create \"Job-Application\" Proof")
    rahul['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Rahul',
            'attr2_referent': 'Kulkarni',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    rahul['job_application_proof'] = \
        await anoncreds.prover_create_proof(rahul['wallet'], rahul['job_application_proof_request'],
                                            rahul['job_application_requested_creds'], rahul['master_secret_id'],
                                            rahul['schemas_for_job_application'],
                                            rahul['cred_defs_for_job_application'],
                                            rahul['revoc_states_for_job_application'])
    print(rahul['job_application_proof'])

    print("\"rahul\" -> Send \"Job-Application\" Proof to theCompany")

    # Over Network
    theCompany['job_application_proof'] = rahul['job_application_proof']
    

    # Validating the verifiable presentation
    job_application_proof_object = json.loads(theCompany['job_application_proof'])

    theCompany['schemas_for_job_application'], theCompany['cred_defs_for_job_application'], \
    theCompany['revoc_ref_defs_for_job_application'], theCompany['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(theCompany['pool'], theCompany['did'],
                                                job_application_proof_object['identifiers'], theCompany['name'])

    print("\"theCompany\" -> Verify \"Job-Application\" Proof from rahul")
    assert 'Bachelor of Science, Marketing' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'Graduated' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Rahul' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Kulkarni' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(theCompany['job_application_proof_request'], theCompany['job_application_proof'],
                                                 theCompany['schemas_for_job_application'],
                                                 theCompany['cred_defs_for_job_application'],
                                                 theCompany['revoc_ref_defs_for_job_application'],
                                                 theCompany['revoc_regs_for_job_application'])
loop = asyncio.get_event_loop()
loop.run_until_complete(run())