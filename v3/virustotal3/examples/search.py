import os
import virustotal3.enterprise
import json

#API_KEY = os.environ['VT_API']
API_KEY = "d8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8"
results = virustotal3.enterprise.search(API_KEY, 'engines:"Mal/Generic-S (PUA)"', order='size-', limit=300, descriptors_only=False)

#print(json.dumps(results, indent=4, sort_keys=True))


# if use descriptors_only=True
# for id in results['data']['attributes']:
#    print(id['sha1'])


for s in range(len(results['data'])):
    print(results['data'][s]['attributes']['sha1'])


try: 

    has_cursor = results['meta']['cursor']
#    print(has_cursor)

    test = True

    while test:

        if has_cursor != None:
            results = virustotal3.enterprise.search(API_KEY, 'engines:"Mal/Generic-S (PUA)"', order='size-', limit=300, descriptors_only=False, cursor=has_cursor)
            #print(json.dumps(results, indent=4, sort_keys=True))
            #for id2 in results['data']['attributes']:
            #    print(id2['sha1'])
            for i in range(len(results['data'])):
                print(results['data'][i]['attributes']['sha1'])
         
            has_cursor = results['meta']['cursor']
            print(has_cursor)
            if has_cursor == None:
                test = False

except:
    print("error")


