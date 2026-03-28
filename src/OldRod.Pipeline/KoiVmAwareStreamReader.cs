
using System;
using AsmResolver;
using AsmResolver.IO;
using AsmResolver.PE.DotNet.Metadata;
using OldRod.Core;
using OldRod.Core.Architecture;

namespace OldRod.Pipeline
{
    public class KoiVmAwareStreamReader : IMetadataStreamReader
    {
        private const string Tag = "KoiStreamReader";
        private readonly IMetadataStreamReader _reader;

        public KoiVmAwareStreamReader(ILogger logger)
            : this("#Koi", logger)
        {
        }

        public KoiVmAwareStreamReader(string koiStreamName, ILogger logger)
        {
            KoiStreamName = koiStreamName ?? throw new ArgumentNullException(nameof(koiStreamName));
            Logger = logger;
            _reader = new DefaultMetadataStreamReader();
        }
        
        public string KoiStreamName
        {
            get;
        }

        public ILogger Logger
        {
            get;
        }

        public IMetadataStream ReadStream(MetadataReaderContext context, MetadataStreamHeader header, ref BinaryStreamReader reader)
        {
            bool hasExpectedName = header.Name == KoiStreamName;
            bool hasKoiSignature = HasKoiSignature(ref reader);

            if (hasExpectedName || hasKoiSignature)
            {
                if (!hasExpectedName && hasKoiSignature)
                {
                    Logger?.Debug(Tag,
                        $"Detected Koi stream in metadata stream {header.Name} using the stream signature.");
                }

                return new KoiStream(header.Name, new DataSegment(reader.ReadToEnd()), Logger);
            }

            return _reader.ReadStream(context, header, ref reader);
        }

        private static bool HasKoiSignature(ref BinaryStreamReader reader)
        {
            uint originalOffset = (uint)reader.Offset;

            try
            {
                return reader.ReadUInt32() == KoiStream.Signature;
            }
            catch
            {
                return false;
            }
            finally
            {
                reader.Offset = originalOffset;
            }
        }
    }
}
