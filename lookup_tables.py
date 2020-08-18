#!/usr/bin/env python3
# Library File for arin_scraper.py
# Written by jack @ nyi
# Licensed under FreeBSD's 3 clause BSD license. see LICENSE

'''Lookup tables, for extremely long lists, dictionaries, and classes to
   keep them out of the mainfile to reduce clutter. Large amounts of static data
   in lookup tables'''

# CIDR notion and the corresponding amount of IPs in their space
cidr_dict = { 16777216:"/8", 8388608:"/9", 4194304:"/10", 2097152:"/11",
              1048576:"/12", 524288:"/13", 262144:"/14", 131072:"/15",
              65536:"/16", 32768:"/17", 16384:"/18", 8192:"/19", 4096:"/20",
              2048:"/21", 1024:"/22", 512:"/23", 256:"/24", 128:"/25", 64:"/26",
              32:"/27", 16:"/28", 8:"/29" }

#Mark's list of countries he needs information on
marksCountries=['AO', 'BJ', 'BW', 'BF', 'BI', 'CM', 'CV', 'CF', 'TD', 'CD', 'GQ',
                'EG', 'ER', 'ET', 'GA', 'GM', 'GH', 'GN', 'GW', 'GY', 'CI', 'KE',
                'LS', 'LY', 'MG', 'MW', 'ML', 'MR', 'MU', 'YT', 'MA', 'MZ', 'NA',
                'NE', 'NG', 'CG', 'RW', 'SN', 'SC', 'SO', 'ZA', 'SZ', 'TZ', 'TG',
                'TN', 'UG', 'EH', 'ZM', 'ZW', 'AP', 'AS', 'AU', 'BD', 'BY', 'BT',
                'MM', 'KH', 'CN', 'CX', 'FJ', 'PF', 'GU', 'HK', 'IN', 'ID', 'JP',
                'KI', 'LA', 'MO', 'MY', 'MV', 'MH', 'MN', 'NP', 'NZ', 'KP', 'PK',
                'PH', 'WS', 'SG', 'KR', 'LK', 'TW', 'TH', 'TO', 'VU', 'VN', 'GL',
                'IS', 'EU', 'DZ', 'HG', 'BN', 'HR', 'CY', 'XK', 'LV', 'MK', 'MT',
                'MD', 'ME', 'RS', 'SK', 'SI', 'AL', 'AD', 'DK', 'FO', 'FR', 'GI',
                'VA', 'IE', 'IM', 'JE', 'LU', 'MC', 'PT', 'ES', 'GB', 'AT', 'BE',
                'BG', 'CH', 'CZ', 'DE', 'EE', 'FI', 'GR', 'HU', 'IT', 'NL', 'LI',
                'LT', 'NO', 'PL', 'RO', 'RU', 'SE', 'UA', 'AF', 'AM', 'AZ', 'BH',
                'IO', 'GE', 'IR', 'IQ', 'IL', 'JO', 'KZ', 'KW', 'KG', 'LB', 'LR',
                'OM', 'QA', 'SA', 'SD', 'SY', 'TJ', 'TR', 'TM', 'AE', 'UZ', 'YE',
                'AG', 'AI', 'AQ', 'AR', 'AW', 'BS', 'BB', 'BZ', 'BM', 'BO', 'BR',
                'VG', 'CL', 'CO', 'CR', 'CU', 'DM', 'DO', 'EC', 'SV', 'FK', 'GD',
                'GT', 'HT', 'HN', 'JM', 'MS', 'MX', 'NI', 'PA', 'PY', 'PE', 'PR',
                'SR', 'TT', 'UY', 'VI', 'VE']

#All ISO 3166-1 country codes.
allCountries  =['AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR',
                'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BY', 'BE',
                'BZ', 'BJ', 'BM', 'BT', 'BO', 'BQ', 'BA', 'BW', 'BV', 'BR', 'IO',
                'BN', 'BG', 'BF', 'BI', 'KH', 'CM', 'CA', 'CV', 'KY', 'CF', 'TD',
                'CL', 'CN', 'CX', 'CC', 'CO', 'KM', 'CG', 'CD', 'CK', 'CR', 'CI',
                'HR', 'CU', 'CW', 'CY', 'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG',
                'SV', 'GQ', 'ER', 'EE', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GF',
                'PF', 'TF', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD',
                'GP', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'VA', 'HN',
                'HK', 'HU', 'IS', 'IN', 'ID', 'IR', 'IQ', 'IE', 'IM', 'IL', 'IT',
                'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'KP', 'KR', 'KW', 'KG',
                'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MO', 'MK',
                'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT',
                'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MS', 'MA', 'MZ', 'MM', 'NA',
                'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MP',
                'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN',
                'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN',
                'LC', 'MF', 'PM', 'VC', 'WS', 'SM', 'ST', 'SA', 'SN', 'RS', 'SC',
                'SL', 'SG', 'SX', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'SS', 'ES',
                'LK', 'SD', 'SR', 'SJ', 'SZ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ',
                'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV',
                'UG', 'UA', 'AE', 'GB', 'US', 'UM', 'UY', 'UZ', 'VU', 'VE', 'VN',
                'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW']

ccLookupTable = {'Eritrea': 'ER', 'Bouvet Island': 'BV', 'Georgia': 'GE',
'Nicaragua': 'NI', 'Philippines': 'PH', 'Pitcairn': 'PN', 'Australia': 'AU',
'Antarctica': 'AQ', 'Finland': 'FI', 'Grenada': 'GD', 'United Arab Emirates': 'AE',
'Faroe Islands': 'FO', 'Monaco': 'MC', 'Niger': 'NE', 'Aland Islands': 'AX',
'Ecuador': 'EC', 'Tanzania, United Republic of': 'TZ', 'Spain': 'ES', 'Tonga': 'TO',
'Latvia': 'LV', 'Burkina Faso': 'BF', 'Brunei Darussalam': 'BN', 'Macao': 'MO',
'Israel': 'IL', 'Panama': 'PA', 'Chile': 'CL', 'Puerto Rico': 'PR', 'South Sudan': 'SS',
'Central African Republic': 'CF', 'Taiwan, Province of China': 'TW', 'Hungary': 'HU',
'Aruba': 'AW', 'Liberia': 'LR', 'Bulgaria': 'BG', 'Romania': 'RO', 'Timor-Leste': 'TL',
'Madagascar': 'MG', 'Congo': 'CG', 'Dominican Republic': 'DO', 'Pakistan': 'PK',
'Samoa': 'WS', 'Anguilla': 'AI', 'Sweden': 'SE', 'Virgin Islands, British': 'VG',
'Serbia': 'RS', 'Indonesia': 'ID', 'Guernsey': 'GG', 'Morocco': 'MA', 'Mauritius': 'MU',
'Syrian Arab Republic': 'SY', 'Papua New Guinea': 'PG', 'United States': 'US',
'Japan': 'JP', 'Tokelau': 'TK', 'Northern Mariana Islands': 'MP',
'Equatorial Guinea': 'GQ', 'Barbados': 'BB', 'Togo': 'TG', 'Curaçao': 'CW',
'Lesotho': 'LS', 'Heard Island and McDonald Islands': 'HM', 'Cocos Keeling Islands': 'CC',
'Singapore': 'SG', 'Croatia': 'HR', 'Suriname': 'SR', 'French Polynesia': 'PF',
'Svalbard and Jan Mayen': 'SJ', 'Cayman Islands': 'KY', 'New Zealand': 'NZ', 'Chad': 'TD',
'Christmas Island': 'CX', 'Cuba': 'CU', 'Saint Pierre and Miquelon': 'PM', 'Jordan': 'JO',
'Greece': 'GR', 'Reunion': 'RE', 'Montenegro': 'ME', 'Holy See Vatican City State': 'VA',
'Saint Martin French part': 'MF', 'French Guiana': 'GF', 'Kazakhstan': 'KZ',
'Costa Rica': 'CR', 'Mali': 'ML', 'Guinea-Bissau': 'GW', 'Botswana': 'BW',
'Nigeria': 'NG', 'Swaziland': 'SZ', 'American Samoa': 'AS', 'Qatar': 'QA',
'Venezuela, Bolivarian Republic of': 'VE', 'Kuwait': 'KW', 'Sudan': 'SD',
'Martinique': 'MQ', 'Vanuatu': 'VU', 'Norfolk Island': 'NF', 'Turkey': 'TR',
'Sao Tome and Principe': 'ST', 'Lao Peoples Democratic Republic': 'LA',
'Wallis and Futuna': 'WF', 'Egypt': 'EG', 'Cook Islands': 'CK', 'Germany': 'DE', 
'United States Minor Outlying Islands': 'UM', 'Virgin Islands, U.S.': 'VI',
'Uzbekistan': 'UZ', 'Guadeloupe': 'GP', 'Lithuania': 'LT', 'Austria': 'AT',
'New Caledonia': 'NC', 'Guatemala': 'GT', 'Andorra': 'AD', 'Gambia': 'GM',
'Slovakia': 'SK', 'Cambodia': 'KH', 'Saint Vincent and the Grenadines': 'VC',
'Belgium': 'BE', 'Bangladesh': 'BD', 'Slovenia': 'SI', 'Honduras': 'HN',
'Mauritania': 'MR', 'Denmark': 'DK', 'Switzerland': 'CH', 'Armenia': 'AM',
'Nauru': 'NR', 'Poland': 'PL', 'Bermuda': 'BM', 'Thailand': 'TH',
'Sint Maarten Dutch part': 'SX', 'Comoros': 'KM', 'Gabon': 'GA', 'Cabo Verde': 'CV',
'Ireland': 'IE', 'Falkland Islands Malvinas': 'FK', 'Namibia': 'NA', 'Iraq': 'IQ',
'Hong Kong': 'HK', 'Seychelles': 'SC', 'Mongolia': 'MN', 'San Marino': 'SM',
'Palau': 'PW', 'Estonia': 'EE', 'Algeria': 'DZ', 'Fiji': 'FJ', 'Kiribati': 'KI',
'Belize': 'BZ', 'Bhutan': 'BT', 'Saint Lucia': 'LC', 'Kenya': 'KE', 'Uruguay': 'UY',
'Belarus': 'BY', 'Greenland': 'GL', 'Iran, Islamic Republic of': 'IR',
'Bonaire, Sint Eustatius and Saba': 'BQ', 'Angola': 'AO', 'Mozambique': 'MZ',
'Maldives': 'MV', 'Colombia': 'CO', 'British Indian Ocean Territory': 'IO',
'Italy': 'IT', 'Guyana': 'GY', 'Côte dIvoire': 'CI', 'France': 'FR', 'Ghana': 'GH',
'Yemen': 'YE', 'Saudi Arabia': 'SA', 'Haiti': 'HT', 'Dominica': 'DM', 'Oman': 'OM',
'Myanmar': 'MM', 'Liechtenstein': 'LI', 'Tajikistan': 'TJ', 'Isle of Man': 'IM',
'Jersey': 'JE', 'Libya': 'LY', 'Congo, the Democratic Republic of the': 'CD',
'Macedonia, the former Yugoslav Republic of': 'MK', 'Argentina': 'AR', 'Cameroon': 'CM',
'Brazil': 'BR', 'Senegal': 'SN', 'Djibouti': 'DJ', 'China': 'CN', 'Albania': 'AL',
'Burundi': 'BI', 'Sri Lanka': 'LK', 'Moldova, Republic of': 'MD', 'Niue': 'NU',
'Saint Helena, Ascension and Tristan da Cunha': 'SH', 'Gibraltar': 'GI',
'Western Sahara': 'EH', 'Sierra Leone': 'SL', 'Tunisia': 'TN', 'Luxembourg': 'LU',
'Mexico': 'MX', 'Iceland': 'IS', 'Mayotte': 'YT',
'Korea, Democratic Peoples Republic of': 'KP', 'Turkmenistan': 'TM', 'Guinea': 'GN',
'Kyrgyzstan': 'KG', 'Uganda': 'UG', 'Canada': 'CA', 'French Southern Territories': 'TF',
'India': 'IN', 'Bahrain': 'BH', 'Jamaica': 'JM', 'Guam': 'GU', 'Viet Nam': 'VN',
'Bolivia, Plurinational State of': 'BO', 'Somalia': 'SO', 'Zambia': 'ZM',
'Montserrat': 'MS', 'United Kingdom': 'GB', 'Ethiopia': 'ET', 'Russian Federation': 'RU',
'Korea, Republic of': 'KR', 'Tuvalu': 'TV', 'Palestine, State of': 'PS',
'El Salvador': 'SV', 'South Georgia and the South Sandwich Islands': 'GS',
'Micronesia, Federated States of': 'FM', 'Cyprus': 'CY', 'Netherlands': 'NL',
'Afghanistan': 'AF', 'Antigua and Barbuda': 'AG', 'Malta': 'MT', 'Nepal': 'NP',
'Saint Kitts and Nevis': 'KN', 'Malawi': 'MW', 'Trinidad and Tobago': 'TT',
'Saint Barthélemy': 'BL', 'Ukraine': 'UA', 'Rwanda': 'RW', 'Malaysia': 'MY',
'Lebanon': 'LB', 'Azerbaijan': 'AZ', 'Marshall Islands': 'MH', 'Norway': 'NO',
'Portugal': 'PT', 'Zimbabwe': 'ZW', 'Solomon Islands': 'SB', 'Peru': 'PE',
'Bosnia and Herzegovina': 'BA', 'Czech Republic': 'CZ', 'Paraguay': 'PY',
'Turks and Caicos Islands': 'TC', 'South Africa': 'ZA', 'Bahamas': 'BS', 'Benin': 'BJ'}

provinceTable = {
    "US" : ['AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA', 'HI',
            'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI',
            'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 'NM', 'NY', 'NC',
            'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT',
            'VT', 'VA', 'WA', 'WV', 'WI', 'WY'],
    
    "CA" : ['AB', 'BC', 'MB', 'NB', 'NL', 'NS', 'PE', 'QC', 'QN', 'SK'],
}

class colors:
    '''Colors class:
    use as colors.subclass.colorname.
    subclasses are fg for foreground, and bg for background
    universal(no subclass) are reset,bold,disable,underline,reverse,
    strikethrough, and invisible
    '''
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'
