function formatTestValue(value) {
  return String(value).trim().toUpperCase();
}

function testFunction() {
  const input = "test";
  const formatted = formatTestValue(input);
  return formatted;
}

export default testFunction;
