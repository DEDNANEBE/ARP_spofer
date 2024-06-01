ARPspoofing, или ARP spoofing, это метод атаки в компьютерных сетях, в основе которого лежит манипуляция протоколом ARP (Address Resolution Protocol). Протокол ARP используется для связи между сетевыми устройствами в локальной сети, чтобы сопоставить IP-адреса с физическими MAC-адресами.

В атаке ARPspoofing злоумышленник отправляет фальшивые ARP-пакеты на целевую локальную сеть. Эти пакеты содержат ложные соответствия между IP-адресами и MAC-адресами. Когда устройство в сети получает такой поддельный ARP-пакет, оно обновляет свою кэш-таблицу ARP, думая, что определенный IP-адрес теперь соответствует другому MAC-адресу. В результате трафик, который должен был быть отправлен на правильное устройство в сети, теперь перенаправляется на устройство, управляемое злоумышленником.

ARPspoofing может использоваться для множества атак, включая перехват трафика, подмену данных, осуществление "человек посередине" (man-in-the-middle), и другие. Это особенно опасно в незащищенных сетях, где у атакующего есть доступ к сети, например, в общедоступных Wi-Fi сетях.

Для защиты от атак ARPspoofing можно использовать криптографические методы аутентификации, например, IPsec, или применять средства безопасности на уровне сетевого оборудования, такие как фильтрация трафика и мониторинг активности ARP.