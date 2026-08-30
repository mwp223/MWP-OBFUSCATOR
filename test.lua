-- Simple test script to demo the obfuscator

local SECRET_KEY = "my_secret_value_123"

local function encrypt(s, key)
    local result = {}
    for i = 1, #s do
        local byte = string.byte(s, i)
        local kbyte = string.byte(key, ((i - 1) % #key) + 1)
        result[i] = string.char(bit32.bxor(byte, kbyte))
    end
    return table.concat(result)
end

local function greet(name)
    print("Hello, " .. name .. "! Key length: " .. #SECRET_KEY)
end

for i = 1, 3 do
    greet("User " .. tostring(i))
end

local data = {10, 20, 30, 40, 50}
local sum = 0
for _, v in ipairs(data) do
    sum = sum + v
end
print("Sum:", sum)

return sum
