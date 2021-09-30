<template>
    <h1>DNS</h1>
    <p>
        RFC: <a href="https://datatracker.ietf.org/doc/html/rfc1035">https://datatracker.ietf.org/doc/html/rfc1035</a>
    </p>
    <h2>Input Hex-Stream of DNS request/response package here <small>(copy it from wireshark)</small>:</h2>
    <p>
        <textarea v-model="data.inputBytestream" :class="classes.input.hasError"></textarea>
    </p>
    <div ref="coloredInput" :class="['quickpreview', classes.input.hasError]">
        <span class="blue" v-if="'header' in data.slices">{{ data.inputBytestream.substr(data.slices.header.s * 2, data.slices.header.l * 2) }}</span>
        <span class="orange" v-if="'qd' in data.slices">{{ data.inputBytestream.substr(data.slices.qd.s * 2, data.slices.qd.l * 2) }}</span>
        <span class="green" v-if="'an' in data.slices">{{ data.inputBytestream.substr(data.slices.an.s * 2, data.slices.an.l * 2) }}</span>
        <span class="violet" v-if="'ns' in data.slices">{{ data.inputBytestream.substr(data.slices.ns.s * 2, data.slices.ns.l * 2) }}</span>
        <span class="turquoise" v-if="'ar' in data.slices">{{ data.inputBytestream.substr(data.slices.ar.s * 2, data.slices.ar.l * 2) }}</span>
    </div>
    <p v-if="coloredInput && coloredInput.textContent !== data.inputBytestream">
        PROBLEM!!!<br>
        Your input is not supported, sorry
    </p>
    <div class="flex" style="margin-top:15px;text-align:left">
        <div>
            <b>Complete Packet</b>
            <pre>
+---------------------+
|        <span class="blue">Header</span>       |
+---------------------+
|       <span class="orange">Question</span>      |
+---------------------+
|        <span class="green">Answer</span>       |
+---------------------+
|      <span class="violet">Authority</span>      |
+---------------------+
|      <span class="turquoise">Additional</span>     |
+---------------------+</pre>
            <label><input type="checkbox" v-model="data.inputs.startAt1"> Start at 1</label>
            <div style="font-family:monospace;text-align:left">
                <template v-for="(c, i) in data.byteArray" :key="i">
                    <div :class="getClassForRow(i)">
                        {{ ((i + (data.inputs.startAt1 ? 1 : 0)) + '').padStart(3, '0') }} {{ (c + '').padStart(3, '0') }} 0x{{ c.toString(16).padStart(2, '0') }}  {{ c.toString(2).padStart(8, '0') }}
                        {{ ['orange','green'].includes(getClassForRow(i)) ? (c >= 'A'.charCodeAt(0) ? String.fromCharCode(c) : '&nbsp;') : '-' }}
                        | {{ data.lineInfos[i] || '-' }}
                    </div>
                </template>
            </div>
        </div>
        <div class="flex" style="flex-direction:column">
            <div class="blue">
                <b>Header</b>
                <div class="flex">
                    <pre>
                                      1  1  1  1  1  1                        1 1 1 1 1 1
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      ID                       |  |{{ byteDiagram.header.txid }}|
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |  |{{ data.parsed.header.flags.qr }}|{{ byteDiagram.header.flags.opcode }}|{{ data.parsed.header.flags.aa }}|{{ data.parsed.header.flags.tc }}|{{ data.parsed.header.flags.rd }}|{{ data.parsed.header.flags.ra }}|{{ byteDiagram.header.flags.z }}|{{ byteDiagram.header.flags.rcode }}|
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    QDCOUNT                    |  |{{ byteDiagram.header.qdcount }}|
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    ANCOUNT                    |  |{{ byteDiagram.header.ancount }}|
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    NSCOUNT                    |  |{{ byteDiagram.header.nscount }}|
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    ARCOUNT                    |  |{{ byteDiagram.header.arcount }}|
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+</pre>
                    <pre style="margin-left:20px">
TxID: {{ data.parsed.header.txid }} | 0x{{ (data.parsed.header.txid || 0).toString(16) }}
QR: {{ ['query', 'response'][data.parsed.header.flags.qr] }}
OpCode: {{ ['QUERY','IQUERY','STATUS'][data.parsed.header.flags.opcode] || 'invalid' }}
AA: {{ data.parsed.header.flags.aa ? '' : 'None' }} Authoritative Answer
TC: {{ data.parsed.header.flags.tc ? '' : 'No' }} Truncation
RD: Recursion {{ data.parsed.header.flags.rd ? '' : 'Not' }} Desired
RA: Recursion {{ data.parsed.header.flags.ra ? '' : 'Not' }} Available
RCODE: {{ ['no error', 'format error', 'server failure', 'name error', 'not implemented', 'refused'][data.parsed.header.flags.rcode] || 'invalid' }}
Questions: {{ data.parsed.header.qdcount }}
Answers: {{ data.parsed.header.ancount }}
Authorities: {{ data.parsed.header.nscount }}
Additionals: {{ data.parsed.header.arcount }}</pre>
                </div>
            </div>
            <div class="orange">
                <b>Question</b>
                <div class="flex">
                    <pre>
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                     QNAME                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QTYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QCLASS                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+</pre>
                </div>
            </div>
            <div class="green">
                <b>Answer</b>
                <div class="flex">
                    <pre>
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                                               /
  /                      NAME                     /
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     CLASS                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TTL                      |
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                   RDLENGTH                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  /                     RDATA                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+</pre>
                </div>
            </div>
        </div>
    </div>
</template>

<script setup>
import {computed, onBeforeMount, reactive, ref, watch} from "vue"
import {parseHeader} from "../parsers/dns/header"

const coloredInput = ref(null)

function deepFreeze(obj) {
    const propNames = Object.getOwnPropertyNames(obj);

    for (let name of propNames) {
        let value = obj[name];
        obj[name] = value && typeof value === "object" ? deepFreeze(value) : value;
    }
    return Object.freeze(obj);
}

const defaultValuesTemplate = deepFreeze({
    offsets: {
        header: 0,
        questions: 999999,
        question: [],
        answers: 999999,
        answer: [],
        authorities: 999999,
        authority: [],
        additionals: 999999,
        additional: [],
    },
    slices: {
        header: {s: 0, e: 11, l: 12}
    },
    parsed: {
        header: {
            flags: {},
        },
        questions: [],
    },
    inputs: {
        startAt1: false,
    },
    lineInfos: ['txid', 'txid', 'flags', 'flags', 'qdcount', 'qdcount', 'ancount', 'ancount', 'nscount', 'nscount', 'arcount', 'arcount'],
})
const defaultValues = JSON.parse(JSON.stringify(defaultValuesTemplate))

const resetToDefaultValues = () => {
    console.log('resetToDefaultValues')
    data.byteArray = []
    data.byteArrayDebugable = []
    data.offsets = defaultValues.offsets
    data.slices = defaultValues.slices
    data.parsed = defaultValues.parsed
    data.inputs.startAt1 = defaultValues.inputs.startAt1
    data.lineInfos = defaultValues.lineInfos
}

onBeforeMount(() => resetToDefaultValues)

const data = reactive({
    byteArray: [],
    byteArrayDebugable: [],
    inputBytestream: '08b70100000100000000000106676f6f676c6503636f6d00000100010000290200000000000000',
    offsets: defaultValues.offsets,
    slices: defaultValues.slices,
    parsed: defaultValues.parsed,
    inputs: {
        startAt1: defaultValues.inputs.startAt1
    },
    lineInfos: defaultValues.lineInfos,
})

const hexStringToByteArray = function (hexString) {
    if (hexString.length % 2 !== 0) {
        throw "Must have an even number of hex digits to convert to bytes"
    }
    const numBytes = hexString.length / 2
    const byteArray = new Uint8Array(numBytes)
    for (let i = 0; i < numBytes; i++) {
        byteArray[i] = parseInt(hexString.substr(i * 2, 2), 16)
    }
    return byteArray
}

const parseBytestream = () => {

    if (!data.inputBytestream || !data.inputBytestream.length || data.inputBytestream.length % 2 !== 0) {
        resetToDefaultValues()
        return
    }

    data.byteArray = hexStringToByteArray(data.inputBytestream)
    data.byteArrayDebugable = Array.from(data.byteArray)
    data.parsed.header = parseHeader(data.byteArray)

    // start the search right after the header
    let startOffset = data.offsets.questions = data.offsets.question[0] = 12

    let nextStartIndex = data.offsets.questions

    if(data.parsed.header.qdcount) {
        data.slices.qd = {s: nextStartIndex}
    }
    // if there are questions => search the end of the questions
    // end of last question + 1 => offset for first answer
    for(let qdCount = 0; qdCount < data.parsed.header.qdcount; qdCount++) {
        data.offsets.question[qdCount] = startOffset
        for(let i = startOffset; i < data.byteArray.length; i++) {
            const c = data.byteArray[i];
            if(c === 0) {
                data.lineInfos[i] = '0x00 qd#' + qdCount
                data.lineInfos[i + 1] = 'qtype'
                data.lineInfos[i + 2] = 'qtype'
                data.lineInfos[i + 3] = 'qclass'
                data.lineInfos[i + 4] = 'qclass'
                startOffset = nextStartIndex = i + 5 /* skip 4 bytes (qtype,qclass) and return index of next byte */
                break
            }
        }
    }
    if(data.parsed.header.qdcount) {
        data.slices.qd.e = startOffset - 1
        data.slices.qd.l = data.slices.qd.e - data.slices.qd.s + 1
        nextStartIndex = data.slices.qd.e + 1
    }

    if(data.parsed.header.ancount) {
        data.slices.an = {s: nextStartIndex}
    }
    // if there are answers => search the end of the answers
    // end of last answers + 1 => offset for first authority
    for(let anCount = 0; anCount < data.parsed.header.ancount; anCount++) {
        data.offsets.answer[anCount] = startOffset
        if(!anCount) data.offsets.answers = startOffset
        for(let i = startOffset; i < data.byteArray.length; i++) {
            const c = data.byteArray[i];
            if(c === 0) {
                const type = [
                    '?', 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT'
                ][(data.byteArray[i] << 8) | data.byteArray[i + 1]] || 'invalid'
                const cls = [
                    '?', 'IN', 'CS', 'CH', 'HS'
                ][(data.byteArray[i] << 2) | data.byteArray[i + 3]] || 'invalid'
                const rdlength = (data.byteArray[i + 8] << 8) | data.byteArray[i + 9]
                data.lineInfos[i]     = 'an#' + anCount + ' 0x00'
                data.lineInfos[i + 1] = 'an#' + anCount + ' type: ' + type
                data.lineInfos[i + 2] = 'an#' + anCount + ' class'
                data.lineInfos[i + 3] = 'an#' + anCount + ' class: ' + cls
                data.lineInfos[i + 4] = 'an#' + anCount + ' ttl'
                data.lineInfos[i + 5] = 'an#' + anCount + ' ttl'
                data.lineInfos[i + 6] = 'an#' + anCount + ' ttl'
                data.lineInfos[i + 7] = 'an#' + anCount + ' ttl'
                data.lineInfos[i + 8] = 'an#' + anCount + ' len'
                data.lineInfos[i + 9] = 'an#' + anCount + ' len: ' + rdlength
                for(let j = 1; j <= rdlength; j++) {
                    data.lineInfos[i + 9 + j] = 'an#' + anCount + ' data #' + j
                }
                startOffset = i + 9 + rdlength + 1
                // data.offsets.authorities = i + 9 + rdlength /* skip 11 bytes (type,class,ttl,rdlength) and rdata and return index of next byte */
                // startOffset = data.offsets.answer[anCount] = data.offsets.authorities
                break
            }
        }
    }
    if(data.parsed.header.ancount) {
        data.slices.an.e = startOffset - 1
        data.slices.an.l = data.slices.an.e - data.slices.an.s + 1
        nextStartIndex = data.slices.an.e + 1
    }

    if(data.parsed.header.nscount) {
        data.slices.ns = {s: nextStartIndex}
    }
    // if there are authorities => search the end of the answers
    // end of last authorities + 1 => offset for first additionals
    for(let nsCount = 0; nsCount < data.parsed.header.nscount; nsCount++) {
        data.offsets.authority[nsCount] = startOffset
        if(!nsCount) data.offsets.answers = startOffset
        for(let i = startOffset; i < data.byteArray.length; i++) {
            const c = data.byteArray[i];
            if(c === 0) {
                const rdlength = (data.byteArray[i + 8] << 8) | data.byteArray[i + 9]
                data.lineInfos[i]     = 'an#' + nsCount + ' 0x00'
                data.lineInfos[i + 1] = 'an#' + nsCount + ' type'
                data.lineInfos[i + 2] = 'an#' + nsCount + ' class'
                data.lineInfos[i + 3] = 'an#' + nsCount + ' class'
                data.lineInfos[i + 4] = 'an#' + nsCount + ' ttl'
                data.lineInfos[i + 5] = 'an#' + nsCount + ' ttl'
                data.lineInfos[i + 6] = 'an#' + nsCount + ' ttl'
                data.lineInfos[i + 7] = 'an#' + nsCount + ' ttl'
                data.lineInfos[i + 8] = 'an#' + nsCount + ' len'
                data.lineInfos[i + 9] = 'an#' + nsCount + ' len: ' + rdlength
                for(let j = 1; j <= rdlength; j++) {
                    data.lineInfos[i + 9 + j] = 'an#' + nsCount + ' data #' + j
                }
                startOffset = i + 9 + rdlength + 1
                // data.offsets.authorities = i + 9 + rdlength /* skip 11 bytes (type,class,ttl,rdlength) and rdata and return index of next byte */
                // startOffset = data.offsets.answer[nsCount] = data.offsets.authorities
                break
            }
        }
    }
    if(data.parsed.header.nscount) {
        data.slices.ns.e = startOffset - 1
        data.slices.ns.l = data.slices.ns.e - data.slices.ns.s + 1
        nextStartIndex = data.slices.ns.e + 1
    }

    if(data.parsed.header.arcount) {
        data.slices.ar = {s: nextStartIndex}
    }
    // if there are additionals => search the end of the additionals
    for(let arCount = 0; arCount < data.parsed.header.arcount; arCount++) {
        data.offsets.additional[arCount] = startOffset
        if(!arCount) data.offsets.additionals = startOffset
        for(let i = startOffset; i < data.byteArray.length; i++) {
            const c = data.byteArray[i];
            if(c === 0) {
                const rdlength = (data.byteArray[i + 9] << 8) | data.byteArray[i + 10]
                data.lineInfos[i] = 'ar#' + arCount + (c === 0 ? ' Name: <root>' : '')
                data.lineInfos[i + 1] = 'ar#' + arCount + ' type'
                data.lineInfos[i + 2] = 'ar#' + arCount + ' type'
                data.lineInfos[i + 3] = 'ar#' + arCount + ' payload size'
                data.lineInfos[i + 4] = 'ar#' + arCount + ' payload size'
                data.lineInfos[i + 5] = 'ar#' + arCount + ' higher bits in extended rcode'
                data.lineInfos[i + 6] = 'ar#' + arCount + ' edns0 version'
                data.lineInfos[i + 7] = 'ar#' + arCount + ' z'
                data.lineInfos[i + 8] = 'ar#' + arCount + ' z'
                data.lineInfos[i + 9] = 'ar#' + arCount + ' len'
                data.lineInfos[i + 10] = 'ar#' + arCount + ' len: ' + rdlength
                startOffset = i + 10 + rdlength + 1
                break
            }
        }
    }
    if(data.parsed.header.arcount) {
        data.slices.ar.e = startOffset - 1
        data.slices.ar.l = data.slices.ar.e - data.slices.ar.s + 1
        // nextStartIndex = data.slices.ar.e + 1
    }
}

watch(() => data.inputBytestream, parseBytestream, {immediate: true})

const getClassForRow = (i) => {
    if(i >= data.offsets.additionals) return 'turquoise'
    if(i < data.offsets.questions) return 'blue'
    if(i < data.offsets.answers && data.parsed.header.qdcount) return 'orange'
    if(i < data.offsets.authorities && data.parsed.header.ancount) return 'green'
    if(i < data.offsets.additionals && data.parsed.header.nscount) return 'violet'
    return 'turquoise'
}

const classes = computed(() => {
    return {
        input: {
            hasError: data.inputBytestream.length % 2 !== 0 ? 'error' : '',
        }
    };
})

function dec2bin(dec) {
    return (dec >>> 0).toString(2);
}
function toByteDiagram(val, numberOfBits) {
    let binStr = dec2bin(val)
    while(binStr.length < numberOfBits)
        binStr = '0' + binStr
    return binStr.split('').join(' ')
}

const byteDiagram = computed(() => {
    return {
        header: {
            txid: toByteDiagram(data.parsed.header.txid || 0, 16),
            flag: toByteDiagram(data.parsed.header.flag, 16),
            flags: {
                opcode: toByteDiagram(data.parsed.header.flags.opcode, 4),
                z: toByteDiagram(data.parsed.header.flags.z, 3),
                rcode: toByteDiagram(data.parsed.header.flags.rcode, 4),
            },
            qdcount: toByteDiagram(data.parsed.header.qdcount, 16),
            ancount: toByteDiagram(data.parsed.header.ancount, 16),
            nscount: toByteDiagram(data.parsed.header.nscount, 16),
            arcount: toByteDiagram(data.parsed.header.arcount, 16),
        }
    }
})
</script>

<style scoped>
textarea {
    height: 60px;
    width: 80%;
}
.quickpreview {
    width: 80%;
    margin: 0 auto;
    word-wrap: break-word;
}
.error {
    border: 2px solid red;
}
.flex {
    display: flex;
}
pre {
    text-align: left;
}
.blue {
    color: dodgerblue;
}
.orange {
    color: darkorange;
}
.green {
    color: green;
}
.violet {
    color: blueviolet;
}
.turquoise {
    color: #38c6b9;
}
</style>