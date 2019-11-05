# Linux kernel exploitation experiments

This is a playground for the Linux kernel exploitation experiments.
Only basic methods. Just for fun.

__Contents:__

  - __drill_mod.c__ - a small Linux kernel module with nice vulnerabilities.
  You can interact with it via a simple debugfs interface.
  - __drill_exploit_uaf.c__ - a basic use-after-free exploit.
  - __drill_exploit_nullderef.c__ - a basic null-ptr-deref exploit, which uses 
  wonderful [mmap_min_addr bypass][1] by Jann Horn.

N.B. Only basic exploit techniques here. So compile your kernel with `x86_64_defconfig`
and run it with `pti=off nokaslr`.

Have fun!

# Временная ремарка от hummelchen

Цель данного форка - добавление некоторых распространенных типов уязвимостей, а также примеров их использования для получения прав суперпользователя. Форк ориентирован на новые ядра, тестирование производится в среде [linux kernel module cheat][2]
Модуль и соответствующие эксплойты необходимо запускать на только виртуальной машине, работоспособность кода между релизами не гарантируется.

[1]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1792&desc=2
[2]: https://github.com/cirosantilli/linux-kernel-module-cheat

# Legal

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
