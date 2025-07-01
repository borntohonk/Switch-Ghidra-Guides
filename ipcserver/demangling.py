import subprocess
import itanium_demangler
import sys

CHECK_CXX_FILT = False

def itanium_demangle_filter(s):
    if s.startswith('N'):
        s = 'Z' + s
    if not s.startswith('_'):
        s = '_' + s
    return s

def itanium_demangle(s):
    python_result = itanium_demangler.parse(itanium_demangle_filter(s))
    if python_result is not None:
        python_result = str(python_result)
    return python_result

demangle_cache = {}
def get_demangled(s):
    if s not in demangle_cache:
        #python_result = itanium_demangle(s)
        #if python_result is None:
        #   #print('demangler failed:', repr(s))
        #   python_result = s
        result = subprocess.check_output(['c++filt', '-n', s]).strip()
        demangle_cache[s] = result.decode('utf-8', errors='replace') if isinstance(result, bytes) else result
        #if CHECK_CXX_FILT:
        #   value = subprocess.check_output(['c++filt', '-n', s]).strip()
        #   if python_result != value:
        #       sys.stderr.write('\n')
        #       sys.stderr.write('mangled: %r\n' % s)
        #       sys.stderr.write('python:  %r\n' % python_result)
        #       sys.stderr.write('c++filt: %r\n' % value)
    return demangle_cache[s]

class Demangler(object):
    def __init__(self, name):
        print(name)
        self.pos = 0
        self.name = name

    def peek(self):
        return self.name[self.pos]

    def getchar(self):
        self.pos += 1
        return self.name[self.pos-1]

    def getchars(self, n):
        return ''.join(self.getchar() for i in range(n))

    def read_string_length(self):
        assert self.peek().isdigit()
        l = ''
        while self.peek().isdigit():
            l += self.getchar()
        return int(l)

    def read_string(self):
        l = self.read_string_length()
        return self.getchars(l)

    def read_template(self):
        assert self.getchar() == 'I'
        parts = []
        while self.peek() != 'E':
            print('read_template:', self.name[self.pos:])
            parts.append(self.parse())
            print('read_template:', parts)
        assert self.getchar() == 'E'
        return '<%s>' % ', '.join(parts)

    def read_name(self):
        assert self.getchar() == 'N'
        parts = []
        while self.peek() != 'E':
            parts.append(self.parse())
            print('read_name:', parts)
        assert self.getchar() == 'E'
        return '::'.join(parts)

    def parse_backref(self):
        assert self.getchar() == 'S'
        backref = ''
        while self.peek() != '_':
            if not self.peek().isdigit():
                print('TODO in parse_back_ref: %r (%r)' % (self.peek(), self.name[self.pos:]))
                return ''
            backref += self.getchar()
        assert self.getchar() == '_'
        result = 'BACKREF_%s_TODO' % backref
        print('parse_backref:', result)
        return result

    def parse_literal(self):
        assert self.getchar() == 'L'
        kind = self.parse()
        #print('TODO in parse_back_ref: %r (%r)' % (self.peek(), self.name[self.pos:]))
        value = self.read_string_length()
        assert self.getchar() == 'E'
        return '(%s)%d' % (kind, value)

    def parse(self):
        c = self.peek()
        if c == 'N':
            return self.read_name()
        elif c == 'I':
            return self.read_template()
        elif c == 'S':
            return self.parse_backref()
        elif c == 'L':
            return self.parse_literal()
        elif c.isdigit():
            return self.read_string()
        else:
            print('TODO in parse: %r (%r)' % (self.peek(), self.name[self.pos:]))
            return self.getchar()


def main():
    tests = [
        ('N2nn2sf4cmif6server22CmifDomainServerObject23CmifDomainServerMessageE',
         'nn::sf::cmif::server::CmifDomainServerObject::CmifDomainServerMessage'),
        ('N2nn2sf4cmif6client6detail13CmifProxyImplINS_8settings22IFactorySettingsServerENS0_4hipc6client18Hipc2ProxyKindBaseILNS7_6detail11MessageTypeE4EEENS0_25StatelessAllocationPolicyINS0_22ExpHeapStaticAllocatorILm16384ES6_EEEES6_EE',
         'nn::sf::cmif::client::detail::CmifProxyImpl<nn::settings::IFactorySettingsServer, nn::sf::hipc::client::Hipc2ProxyKindBase<(nn::sf::hipc::detail::MessageType)4>, nn::sf::StatelessAllocationPolicy<nn::sf::ExpHeapStaticAllocator<16384ul, nn::settings::IFactorySettingsServer> >, nn::settings::IFactorySettingsServer>'),
        ('N2nn2sf4hipc6client12_GLOBAL__N_119HipcManagerAccessorE',
         'nn::sf::hipc::client::(anonymous namespace)::HipcManagerAccessor'),
        ('_ZTVN2nn5fssrv35MemoryResourceFromStandardAllocatorE',
         'vtable for nn::fssrv::MemoryResourceFromStandardAllocator'),
        ('_ZN2nn7nlibsdk4heap12TlsHeapCache17ReallocFunc_Mode0INSt3__117integral_constantIbLb1EEEEEiPS2_PvmPS8_',
         'int nn::nlibsdk::heap::TlsHeapCache::ReallocFunc_Mode0<std::__1::integral_constant<bool, true> >(nn::nlibsdk::heap::TlsHeapCache*, void*, unsigned long, void**)'),
        ('_ZN2nn2gc6detail11AsicHandlerD2Ev',
         'nn::gc::detail::AsicHandler::~AsicHandler()'),
        ('_ZN3nne7prfile224PFCODE_CP932_Unicode2OEMEPKtPa',
         'nne::prfile2::PFCODE_CP932_Unicode2OEM(unsigned short const*, signed char*)'),
    ]

    d = Demangler('N2nn2sf4cmif6server22CmifDomainServerObject23CmifDomainServerMessageE')
    print(d.read_name())

    d = Demangler('N2nn2sf4hipc6client12_GLOBAL__N_119HipcManagerAccessorE')
    print(d.read_name())

    d = Demangler('N2nn2sf4cmif6client6detail13CmifProxyImplINS_8settings22IFactorySettingsServerENS0_4hipc6client18Hipc2ProxyKindBaseILNS7_6detail11MessageTypeE4EEENS0_25StatelessAllocationPolicyINS0_22ExpHeapStaticAllocatorILm16384ES6_EEEES6_EE')
    print(d.read_name())

if __name__ == '__main__':
    main()
